use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

pub const EVENT_ANOMALY_DETECTED: &str = "defense.anomaly.detected";
pub const EVENT_THREAT_BLOCKED: &str = "defense.threat.blocked";
pub const EVENT_POLICY_VIOLATION: &str = "defense.policy.violation";
pub const EVENT_RUNTIME_VERIFIED: &str = "defense.runtime.verified";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnomalyDetected {
    pub tenant_id: String,
    pub anomaly_id: String,
    pub anomaly_type: String,
    pub severity: String,
    pub source: String,
    pub description: String,
    pub confidence: f64,
    pub detected_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatBlocked {
    pub tenant_id: String,
    pub threat_id: String,
    pub threat_type: String,
    pub source_ip: Option<String>,
    pub action_taken: String,
    pub blocked_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyViolation {
    pub tenant_id: String,
    pub violation_id: String,
    pub policy_id: String,
    pub resource: String,
    pub action: String,
    pub violation_details: String,
    pub occurred_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeVerified {
    pub tenant_id: String,
    pub service_name: String,
    pub verification_result: String,
    pub verified_at: DateTime<Utc>,
}
