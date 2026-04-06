//! Example: query DRM/GPU information.

fn main() {
    let cards = match agnosys::drm::enumerate_cards() {
        Ok(c) => c,
        Err(e) => {
            println!("No DRM devices: {e}");
            return;
        }
    };

    if cards.is_empty() {
        println!("No GPU cards found");
        return;
    }

    for path in &cards {
        let dev = match agnosys::drm::Device::open(path) {
            Ok(d) => d,
            Err(e) => {
                println!("{}: failed to open: {e}", path.display());
                continue;
            }
        };

        let ver = dev.version().unwrap();
        println!(
            "{}: {} v{}.{}.{}",
            path.display(),
            ver.name,
            ver.major,
            ver.minor,
            ver.patchlevel
        );
        println!("  Description: {}", ver.desc);

        if let Ok(dumb) = dev.supports_dumb_buffer() {
            println!("  Dumb buffer:  {dumb}");
        }

        if let Ok(res) = dev.mode_resources() {
            println!("  CRTCs:        {}", res.crtc_ids.len());
            println!("  Connectors:   {}", res.connector_ids.len());
            println!("  Encoders:     {}", res.encoder_ids.len());
            println!("  Max res:      {}x{}", res.max_width, res.max_height);

            for &cid in &res.connector_ids {
                if let Ok(conn) = dev.connector_info(cid) {
                    println!(
                        "    Connector {}: {:?} ({:?}) {}x{}mm",
                        conn.id, conn.connector_type, conn.status, conn.mm_width, conn.mm_height
                    );
                }
            }
        }
    }
}
