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
    fn init_with_level_trace() {
        init_with_level("trace");
    }

    #[test]
    fn init_with_level_debug() {
        init_with_level("debug");
    }

    #[test]
    fn init_with_level_info() {
        init_with_level("info");
    }

    #[test]
    fn init_with_level_warn() {
        init_with_level("warn");
    }

    #[test]
    fn init_with_level_error() {
        init_with_level("error");
    }

    #[test]
    fn init_with_level_off() {
        init_with_level("off");
    }

    #[test]
    fn double_init_is_safe() {
        init();
        init(); // second call should be a no-op (try_init)
    }

    #[test]
    fn init_with_invalid_level_does_not_panic() {
        // Invalid level should fall back gracefully via EnvFilter::new
        init_with_level("not_a_real_level");
    }
}
