//! Observability crate for Trust OS.
//!
//! Provides structured logging, metrics collection, and distributed tracing
//! using OpenTelemetry and Prometheus.

pub mod health;
pub mod metrics;
pub mod tracing_setup;

pub use health::*;
pub use metrics::*;
pub use tracing_setup::*;

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

/// Request metrics collector
pub struct RequestMetrics {
    pub total_requests: AtomicU64,
    pub successful_requests: AtomicU64,
    pub failed_requests: AtomicU64,
    pub request_durations: Vec<AtomicU64>,
    pub start_times: HashMap<String, Instant>,
}

impl RequestMetrics {
    pub fn new() -> Self {
        Self {
            total_requests: AtomicU64::new(0),
            successful_requests: AtomicU64::new(0),
            failed_requests: AtomicU64::new(0),
            request_durations: Vec::new(),
            start_times: HashMap::new(),
        }
    }

    pub fn record_request_start(&mut self, request_id: String) {
        self.start_times.insert(request_id, Instant::now());
        self.total_requests.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_request_end(&mut self, request_id: &str, success: bool) {
        self.start_times.remove(request_id);
        if success {
            self.successful_requests.fetch_add(1, Ordering::Relaxed);
        } else {
            self.failed_requests.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn success_rate(&self) -> f64 {
        let total = self.total_requests.load(Ordering::Relaxed);
        let success = self.successful_requests.load(Ordering::Relaxed);
        if total == 0 {
            return 100.0;
        }
        (success as f64 / total as f64) * 100.0
    }

    pub fn total(&self) -> u64 {
        self.total_requests.load(Ordering::Relaxed)
    }
}

impl Default for RequestMetrics {
    fn default() -> Self {
        Self::new()
    }
}

/// Observability configuration
#[derive(Debug, Clone)]
pub struct ObservabilityConfig {
    pub service_name: String,
    pub service_version: String,
    pub environment: String,
    pub log_level: String,
    pub enable_tracing: bool,
    pub enable_metrics: bool,
    pub metrics_port: u16,
    pub jaeger_endpoint: Option<String>,
    pub prometheus_endpoint: Option<String>,
}

impl ObservabilityConfig {
    pub fn from_env() -> Self {
        Self {
            service_name: std::env::var("SERVICE_NAME").unwrap_or_else(|_| "trust-os".into()),
            service_version: std::env::var("SERVICE_VERSION").unwrap_or_else(|_| "0.1.0".into()),
            environment: std::env::var("ENVIRONMENT").unwrap_or_else(|_| "development".into()),
            log_level: std::env::var("LOG_LEVEL").unwrap_or_else(|_| "info".into()),
            enable_tracing: std::env::var("ENABLE_TRACING")
                .unwrap_or_else(|_| "true".into())
                .parse()
                .unwrap_or(true),
            enable_metrics: std::env::var("ENABLE_METRICS")
                .unwrap_or_else(|_| "true".into())
                .parse()
                .unwrap_or(true),
            metrics_port: std::env::var("METRICS_PORT")
                .unwrap_or_else(|_| "9090".into())
                .parse()
                .unwrap_or(9090),
            jaeger_endpoint: std::env::var("JAEGER_ENDPOINT").ok(),
            prometheus_endpoint: std::env::var("PROMETHEUS_ENDPOINT").ok(),
        }
    }
}

/// Initialize observability for a service
pub fn init_observability(config: &ObservabilityConfig) {
    init_tracing(
        &config.service_name,
        &config.service_version,
        &config.environment,
        &config.log_level,
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_request_metrics() {
        let mut metrics = RequestMetrics::new();
        metrics.record_request_start("req-1".into());
        metrics.record_request_end("req-1", true);
        assert_eq!(metrics.total(), 1);
        assert_eq!(metrics.success_rate(), 100.0);
    }

    #[test]
    fn test_request_metrics_failure() {
        let mut metrics = RequestMetrics::new();
        metrics.record_request_start("req-1".into());
        metrics.record_request_end("req-1", false);
        assert_eq!(metrics.total(), 1);
        assert_eq!(metrics.success_rate(), 0.0);
    }

    #[test]
    fn test_observability_config_defaults() {
        let config = ObservabilityConfig {
            service_name: "test".into(),
            service_version: "1.0".into(),
            environment: "test".into(),
            log_level: "info".into(),
            enable_tracing: true,
            enable_metrics: true,
            metrics_port: 9090,
            jaeger_endpoint: None,
            prometheus_endpoint: None,
        };
        assert_eq!(config.metrics_port, 9090);
    }
}
