use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

pub const EVENT_TELEMETRY_RECEIVED: &str = "telemetry.received";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryReceived {
    pub tenant_id: String,
    pub source: String,
    pub telemetry_type: String,
    pub data: std::collections::HashMap<String, String>,
    pub received_at: DateTime<Utc>,
}
