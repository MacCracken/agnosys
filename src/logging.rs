//! Structured logging for agnosys via `AGNOSYS_LOG` env var.

pub fn init() {
    init_with_level("info");
}

pub fn init_with_level(default_level: &str) {
    use tracing_subscriber::EnvFilter;
    use tracing_subscriber::fmt;
    use tracing_subscriber::prelude::*;

    let filter =
        EnvFilter::try_from_env("AGNOSYS_LOG").unwrap_or_else(|_| EnvFilter::new(default_level));

    let _ = tracing_subscriber::registry()
        .with(fmt::layer().with_target(true).with_thread_ids(true))
        .with(filter)
        .try_init();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn init_does_not_panic() {
        init();
    }

    #[test]
    fn init_with_level_does_not_panic() {
        init_with_level("debug");
    }

    #[test]
    fn init_with_level_warn() {
        init_with_level("warn");
    }

    #[test]
    fn double_init_is_safe() {
        init();
        init(); // second call should be a no-op (try_init)
    }
}
