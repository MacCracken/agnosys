# Contributing to Agnosys

Thank you for your interest in contributing to Agnosys.

## Development Workflow

1. Fork and clone the repository
2. Create a feature branch from `main`
3. Make your changes
4. Run `make check` to validate
5. Open a pull request

## Prerequisites

- Rust stable (MSRV 1.89)
- Components: `rustfmt`, `clippy`
- Optional: `cargo-audit`, `cargo-deny`, `cargo-llvm-cov`

## Makefile Targets

| Command | Description |
|---------|-------------|
| `make check` | fmt + clippy + test + audit |
| `make fmt` | Check formatting |
| `make clippy` | Lint with `-D warnings` |
| `make test` | Run test suite |
| `make audit` | Security audit |
| `make deny` | Supply chain checks |
| `make bench` | Run benchmarks with history tracking |
| `make coverage` | Generate coverage report |
| `make doc` | Build documentation |

## Adding a Module

1. Create `src/module_name.rs` with module doc comment
2. Add feature flag to `Cargo.toml` under `[features]`
3. Add `#[cfg(feature = "module_name")] pub mod module_name;` to `src/lib.rs`
4. Add tests in the module (`#[cfg(test)] mod tests`)
5. Add benchmarks in `benches/benchmarks.rs`
6. Update the consumer map in `CLAUDE.md` and README
7. Run `make check` and `make bench`

If the module requires an external dependency, gate it behind its feature flag using `dep:` syntax.

## Code Style

- `cargo fmt` — mandatory
- `cargo clippy -- -D warnings` — zero warnings
- Doc comments on all public items
- `#[non_exhaustive]` on public enums
- `#[must_use]` on pure functions
- `#[inline]` on hot-path functions
- `write!` over `format!` — avoid temporary allocations
- No `unwrap()` or `panic!()` in library code
- No `println!` — use `tracing` for logging

## Testing

- Unit tests colocated in modules (`#[cfg(test)] mod tests`)
- Integration tests in `tests/`
- Feature-gated tests with `#[cfg(feature = "...")]`
- Target: 80%+ line coverage

## Commits

- Use conventional-style messages
- One logical change per commit

## License

By contributing, you agree that your contributions will be licensed under GPL-3.0.
