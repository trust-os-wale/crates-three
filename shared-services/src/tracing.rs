use opentelemetry::global;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter, Registry};

pub struct TracingConfig {
    pub service_name: String,
    pub log_level: String,
    pub enable_json: bool,
}

impl Default for TracingConfig {
    fn default() -> Self {
        Self {
            service_name: "trust-os".into(),
            log_level: "info".into(),
            enable_json: true,
        }
    }
}

pub fn init_tracing(config: TracingConfig) {
    let env_filter = EnvFilter::new(&config.log_level);

    if config.enable_json {
        Registry::default()
            .with(env_filter)
            .with(tracing_subscriber::fmt::layer().json())
            .init();
    } else {
        Registry::default()
            .with(env_filter)
            .with(tracing_subscriber::fmt::layer())
            .init();
    }

    tracing::info!(
        service = %config.service_name,
        log_level = %config.log_level,
        "Tracing initialized"
    );
}

pub fn shutdown_tracing() {
    global::shutdown_tracer_provider();
}
