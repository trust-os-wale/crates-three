use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

pub const EVENT_SECURITY_ALERT_CREATED: &str = "security.alert_created";
pub const EVENT_SECURITY_INCIDENT_CREATED: &str = "security.incident_created";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityAlertCreated {
    pub tenant_id: String,
    pub alert_id: String,
    pub alert_type: String,
    pub severity: String,
    pub source: String,
    pub description: String,
    pub affected_resources: Vec<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityIncidentCreated {
    pub tenant_id: String,
    pub incident_id: String,
    pub incident_type: String,
    pub severity: String,
    pub status: String,
    pub description: String,
    pub affected_resources: Vec<String>,
    pub assigned_to: Option<String>,
    pub created_at: DateTime<Utc>,
}
