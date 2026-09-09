use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

pub const EVENT_INTEGRATION_CONNECTED: &str = "integration.connected";
pub const EVENT_INTEGRATION_FAILED: &str = "integration.failed";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrationConnected {
    pub tenant_id: String,
    pub integration_id: String,
    pub integration_type: String,
    pub provider: String,
    pub connected_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrationFailed {
    pub tenant_id: String,
    pub integration_id: String,
    pub integration_type: String,
    pub provider: String,
    pub error: String,
    pub failed_at: DateTime<Utc>,
}
