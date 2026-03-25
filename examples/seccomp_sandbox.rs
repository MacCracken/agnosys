//! Example: build and inspect a seccomp BPF filter (does NOT load it).

fn main() {
    let filter = agnosys::security::create_basic_seccomp_filter().unwrap();

    println!("Seccomp filter built:");
    println!("  BPF bytes: {}", filter.len());
    println!("  Default action: kill process");
    println!();
    println!("(Not loading — would restrict this process)");
}
