use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

pub const EVENT_AUDIT_RECORDED: &str = "audit.event.recorded";
pub const EVENT_AUDIT_CHAIN_VERIFIED: &str = "audit.chain.verified";
pub const EVENT_AUDIT_ANOMALY_DETECTED: &str = "audit.anomaly.detected";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditRecorded {
    pub tenant_id: String,
    pub event_id: String,
    pub event_type: String,
    pub actor_id: String,
    pub actor_type: String,
    pub resource_type: String,
    pub resource_id: String,
    pub action: String,
    pub changes: HashMap<String, String>,
    pub hash: String,
    pub previous_hash: String,
    pub sequence: u64,
    pub recorded_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditChainVerified {
    pub tenant_id: String,
    pub from_event_id: String,
    pub to_event_id: String,
    pub chain_intact: bool,
    pub verified_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditAnomalyDetected {
    pub tenant_id: String,
    pub event_id: String,
    pub anomaly_type: String,
    pub severity: String,
    pub description: String,
    pub detected_at: DateTime<Utc>,
}
