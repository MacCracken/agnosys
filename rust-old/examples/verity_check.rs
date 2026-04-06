//! Example: check dm-verity support and show hash algorithms.

fn main() -> agnosys::error::Result<()> {
    // Check if dm-verity is supported on this system
    let supported = agnosys::dmverity::verity_supported();
    println!("dm-verity supported: {supported}");

    // Show available hash algorithms and their expected digest lengths
    let algorithms = [
        agnosys::dmverity::VerityHashAlgorithm::Sha256,
        agnosys::dmverity::VerityHashAlgorithm::Sha512,
    ];
    println!("\nSupported hash algorithms:");
    for alg in &algorithms {
        println!("  {} — {} hex chars", alg, alg.hash_hex_len());
    }

    // Validate a sample root hash
    let sample_hash = "a".repeat(64);
    match agnosys::dmverity::validate_root_hash(
        &sample_hash,
        agnosys::dmverity::VerityHashAlgorithm::Sha256,
    ) {
        Ok(()) => println!("\nSample SHA-256 root hash: valid format"),
        Err(e) => println!("\nSample SHA-256 root hash: {e}"),
    }

    Ok(())
}
