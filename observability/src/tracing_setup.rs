use tracing_subscriber::{fmt, util::SubscriberInitExt, EnvFilter};

pub fn init_tracing(service_name: &str, service_version: &str, environment: &str, log_level: &str) {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(log_level));

    fmt::Subscriber::builder()
        .with_env_filter(filter)
        .with_target(true)
        .with_thread_ids(true)
        .with_file(true)
        .with_line_number(true)
        .json()
        .finish()
        .init();

    tracing::info!(
        service_name,
        service_version,
        environment,
        "Tracing initialized"
    );
}

pub fn init_tracing_simple(service_name: &str) {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    fmt::Subscriber::builder()
        .with_env_filter(filter)
        .with_target(true)
        .finish()
        .init();

    tracing::info!(service_name, "Tracing initialized");
}

pub fn shutdown_tracing() {
    tracing::info!("Shutting down tracing");
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_tracing_init() {
        init_tracing_simple("test-service");
        tracing::info!("Test message");
    }
}
