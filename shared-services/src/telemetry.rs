use std::sync::OnceLock;
use tracing_subscriber::prelude::*;
use tracing_subscriber::{util::SubscriberInitExt, EnvFilter, Registry};

static TELEMETRY_INIT: OnceLock<()> = OnceLock::new();

pub struct TelemetryConfig {
    pub service_name: String,
    pub service_version: String,
    pub environment: String,
    pub jaeger_endpoint: Option<String>,
    pub log_level: String,
}

pub struct SovereignTelemetry;

impl SovereignTelemetry {
    pub fn init(config: TelemetryConfig) -> Self {
        TELEMETRY_INIT.get_or_init(|| {
            let env_filter = EnvFilter::new(&config.log_level);

            Registry::default()
                .with(env_filter)
                .with(tracing_subscriber::fmt::layer().json())
                .init();

            tracing::info!(
                service = %config.service_name,
                version = %config.service_version,
                environment = %config.environment,
                "Sovereign Telemetry initialized"
            );
        });

        SovereignTelemetry
    }

    pub fn shutdown() {
        opentelemetry::global::shutdown_tracer_provider();
    }
}

pub fn current_span() -> tracing::Span {
    tracing::Span::current()
}

pub fn add_span_attribute(key: &str, value: &str) {
    tracing::Span::current().record(key, value);
}
