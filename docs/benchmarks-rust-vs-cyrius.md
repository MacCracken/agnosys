# Rust vs Cyrius — Final Benchmark Comparison

Last Rust benchmarks taken at agnosys 0.50.0 (Rust, 29,257 lines, 147 criterion benchmarks).
Cyrius benchmarks from agnosys 0.97.1 (Cyrius 3.2.5, 9,884 lines, 30 batch-amortized benchmarks).

All benchmarks run on the same machine: AMD Ryzen 7 5800H, Linux x86_64.

## Head-to-Head: Comparable Benchmarks

| Benchmark | Rust | Cyrius | Ratio | Winner |
|-----------|------|--------|-------|--------|
| getpid | 308ns | 305ns | 1.0x | parity |
| getuid | 292ns | 286ns | 1.0x | parity |
| is_root | 292ns | 331ns | 1.1x | parity |
| from_errno | 11ns | 18ns | 1.6x | Rust |
| wrap_syscall_ok | 306ns | 320ns | 1.0x | parity |
| query_sysinfo | 467ns | 1000ns | 2.1x | Rust |
| validate_cmdline | 373ns | 536ns | 1.4x | Rust |
| compare_versions | 74ns | 143ns | 1.9x | Rust |
| validate_pin (valid) | 73ns | 249ns | 3.4x | Rust |
| validate_pin (invalid) | 57ns | 9ns | 0.2x | **Cyrius 6x** |
| mac_default_profile | 275ns | 409ns | 1.5x | Rust |
| slot_other | ~1ns | 2ns | ~2x | parity |
| is_enforcing | ~1ns | 2ns | ~2x | parity |

## Cyrius-Only Benchmarks (no Rust equivalent)

| Benchmark | Cyrius |
|-----------|--------|
| syserr_pack | 2ns |
| ok_create | 14ns |
| syscall_name_to_nr_hit | 106ns |
| syscall_name_to_nr_miss | 45ns |
| ct_streq_equal | 247ns |
| ct_streq_diff | 236ns |
| is_dangerous_token_hit | 126ns |
| is_dangerous_token_miss | 119ns |
| validate_ver_good | 89ns |
| mac_file_exists_hit | 1us |
| mac_file_exists_miss | 1us |
| state_str | 2ns |
| parse_subsystem | 34ns |
| starts_with_hit | 34ns |
| starts_with_miss | 19ns |
| streq_16ch | 82ns |
| strlen_16ch | 39ns |
| memeq_16 | 39ns |
| map_get_hit | 54ns |
| map_get_miss | 44ns |

## Build & Size Comparison

| Metric | Rust | Cyrius | Ratio |
|--------|------|--------|-------|
| Source lines | 29,257 | 9,884 | **3.0x smaller** |
| Binary size | 6.9MB (rlib) | 55,688 bytes | **130x smaller** |
| Compile time | 11.7s | 35ms | **334x faster** |
| Dependencies | 8 crates | 0 | **zero-dep** |
| Modules | 20 | 20 | parity |
| Tests | 1,625 | 197 | Rust (unit tests) |
| Benchmarks | 147 | 30 | Rust (criterion) |

## Analysis

**Syscall wrappers** (getpid, getuid, is_root, wrap_syscall): At parity. Both implementations
are thin wrappers around the same Linux syscalls — the kernel call dominates.

**Pure computation** (from_errno, compare_versions, validate_cmdline, validate_pin valid):
Rust is 1.4-3.4x faster. Rust's LLVM backend optimizes string parsing and branch prediction
better than Cyrius's single-pass x86 codegen. The gap is acceptable for cold-path operations.

**Early-exit paths** (validate_pin invalid): Cyrius is 6x faster. Cyrius's packed error
encoding (`kind << 16 | errno`) returns in 9ns vs Rust's heap-allocated error at 57ns.

**Compilation**: Cyrius compiles 334x faster. No dependency resolution, no LLVM, no linking.
The entire project compiles in 35ms.

**Binary size**: 130x smaller. Cyrius produces a static ELF with zero dependencies.
Rust's rlib includes std, serde, sha2, and 5 other crates.

---

*Rust benchmarks from agnosys 0.50.0 (2026-04-02), criterion 0.5.*
*Cyrius benchmarks from agnosys 0.97.1 (2026-04-09), batch-amortized 10K iters x 100 rounds.*
*Rust source preserved in git history (removed at 0.97.1).*
