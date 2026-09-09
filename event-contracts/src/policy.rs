use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

pub const EVENT_POLICY_EVALUATED: &str = "policy.evaluated";
pub const EVENT_POLICY_DENIED: &str = "policy.denied";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyEvaluated {
    pub tenant_id: String,
    pub policy_id: String,
    pub resource: String,
    pub action: String,
    pub decision: String,
    pub evaluated_by: String,
    pub evaluated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyDenied {
    pub tenant_id: String,
    pub policy_id: String,
    pub resource: String,
    pub action: String,
    pub reason: String,
    pub denied_by: String,
    pub denied_at: DateTime<Utc>,
}
