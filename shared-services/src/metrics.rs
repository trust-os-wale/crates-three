use std::sync::OnceLock;

static METRICS_INIT: OnceLock<()> = OnceLock::new();

pub struct SovereignMetrics {
    #[allow(dead_code)]
    service_name: String,
}

impl SovereignMetrics {
    pub fn new(service_name: &str) -> Self {
        METRICS_INIT.get_or_init(|| {
            metrics::describe_counter!("sovereign_requests_total", "Total requests");
            metrics::describe_histogram!("sovereign_request_duration_seconds", "Request duration");
            metrics::describe_gauge!("sovereign_active_connections", "Active connections");
            metrics::describe_counter!("sovereign_events_total", "Total events");
            metrics::describe_gauge!("sovereign_governance_score", "Governance score");
            metrics::describe_gauge!("sovereign_risk_score", "Risk score");
            metrics::describe_gauge!("sovereign_trust_score", "Trust score");
        });

        Self {
            service_name: service_name.to_string(),
        }
    }

    pub fn record_request(&self, _method: &str, _path: &str, _status: u16, duration_secs: f64) {
        metrics::counter!("sovereign_requests_total", 1);
        metrics::histogram!("sovereign_request_duration_seconds", duration_secs);
    }

    pub fn set_active_connections(&self, count: u64) {
        metrics::gauge!("sovereign_active_connections", count as f64);
    }

    pub fn record_event(&self, _event_type: &str, _tenant_id: &str) {
        metrics::counter!("sovereign_events_total", 1);
    }

    pub fn record_governance_score(&self, _tenant_id: &str, score: f64) {
        metrics::gauge!("sovereign_governance_score", score);
    }

    pub fn record_risk_score(&self, _tenant_id: &str, score: f64) {
        metrics::gauge!("sovereign_risk_score", score);
    }

    pub fn record_trust_score(&self, _tenant_id: &str, score: f64) {
        metrics::gauge!("sovereign_trust_score", score);
    }

    pub async fn encode_prometheus(&self) -> String {
        String::from("sovereign_metrics_v6")
    }
}
