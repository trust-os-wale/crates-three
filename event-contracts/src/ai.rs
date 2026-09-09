use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

pub const EVENT_AI_INFERENCE_CREATED: &str = "ai.inference_created";
pub const EVENT_AI_RECOMMENDATION_CREATED: &str = "ai.recommendation_created";
pub const EVENT_AI_ACTION_APPROVED: &str = "ai.action_approved";
pub const EVENT_AI_ACTION_REJECTED: &str = "ai.action_rejected";
pub const EVENT_AI_ACTION_EXECUTED: &str = "ai.action_executed";
pub const EVENT_AI_ACTION_VERIFIED: &str = "ai.action_verified";

// AI Entity Governance events
pub const EVENT_AI_ENTITY_REGISTERED: &str = "ai.entity.registered";
pub const EVENT_AI_ENTITY_VERIFIED: &str = "ai.entity.verified";
pub const EVENT_AI_ENTITY_STATUS_CHANGED: &str = "ai.entity.status_changed";
pub const EVENT_AI_RISK_CHANGED: &str = "ai.entity.risk_changed";
pub const EVENT_AI_TRUST_CHANGED: &str = "ai.entity.trust_changed";
pub const EVENT_AI_POLICY_VIOLATION: &str = "ai.entity.policy_violation";
pub const EVENT_AI_BEHAVIOUR_ANOMALY: &str = "ai.entity.behaviour_anomaly";
pub const EVENT_AI_SECURITY_INCIDENT: &str = "ai.entity.security_incident";
pub const EVENT_AI_ACTION_REQUESTED: &str = "ai.entity.action_requested";
pub const EVENT_AI_ACTION_AUTHORIZED: &str = "ai.entity.action_authorized";
pub const EVENT_AI_ACTION_DENIED: &str = "ai.entity.action_denied";
pub const EVENT_AI_PRIVILEGE_RESTRICTED: &str = "ai.entity.privilege_restricted";
pub const EVENT_AI_PRIVILEGE_REVOKED: &str = "ai.entity.privilege_revoked";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiInferenceCreated {
    pub tenant_id: String,
    pub inference_id: String,
    pub model_id: String,
    pub input: String,
    pub output: String,
    pub confidence: f64,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiRecommendationCreated {
    pub tenant_id: String,
    pub recommendation_id: String,
    pub source_inference_id: Option<String>,
    pub recommendation_type: String,
    pub description: String,
    pub confidence: f64,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiActionApproved {
    pub tenant_id: String,
    pub action_id: String,
    pub recommendation_id: Option<String>,
    pub approved_by: String,
    pub approved_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiActionRejected {
    pub tenant_id: String,
    pub action_id: String,
    pub recommendation_id: Option<String>,
    pub rejected_by: String,
    pub reason: String,
    pub rejected_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiActionExecuted {
    pub tenant_id: String,
    pub action_id: String,
    pub result: String,
    pub executed_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiActionVerified {
    pub tenant_id: String,
    pub action_id: String,
    pub verified_by: String,
    pub verification_result: String,
    pub verified_at: DateTime<Utc>,
}

// AI Entity Governance event payloads

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiEntityRegistered {
    pub tenant_id: String,
    pub entity_id: String,
    pub entity_name: String,
    pub entity_type: String,
    pub owner_id: String,
    pub registered_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiEntityVerified {
    pub tenant_id: String,
    pub entity_id: String,
    pub verifier_id: String,
    pub verified_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiEntityStatusChanged {
    pub tenant_id: String,
    pub entity_id: String,
    pub old_status: String,
    pub new_status: String,
    pub reason: Option<String>,
    pub changed_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiRiskChanged {
    pub tenant_id: String,
    pub entity_id: String,
    pub old_score: f64,
    pub new_score: f64,
    pub risk_level: String,
    pub risk_factors: Vec<String>,
    pub changed_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiTrustChanged {
    pub tenant_id: String,
    pub entity_id: String,
    pub old_score: f64,
    pub new_score: f64,
    pub trust_factors: Vec<String>,
    pub changed_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiPolicyViolation {
    pub tenant_id: String,
    pub entity_id: String,
    pub policy_id: String,
    pub policy_name: String,
    pub violation_details: String,
    pub detected_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiBehaviourAnomaly {
    pub tenant_id: String,
    pub entity_id: String,
    pub anomaly_score: f64,
    pub anomaly_description: String,
    pub detected_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiSecurityIncident {
    pub tenant_id: String,
    pub entity_id: String,
    pub incident_id: String,
    pub incident_type: String,
    pub severity: String,
    pub description: String,
    pub detected_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiActionRequested {
    pub tenant_id: String,
    pub entity_id: String,
    pub request_id: String,
    pub action: String,
    pub resource: String,
    pub requested_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiActionAuthorized {
    pub tenant_id: String,
    pub entity_id: String,
    pub request_id: String,
    pub action: String,
    pub resource: String,
    pub decision: String,
    pub authorized_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiActionDenied {
    pub tenant_id: String,
    pub entity_id: String,
    pub request_id: String,
    pub action: String,
    pub resource: String,
    pub reason: String,
    pub denied_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiPrivilegeRestricted {
    pub tenant_id: String,
    pub entity_id: String,
    pub restricted_by: String,
    pub restrictions: Vec<String>,
    pub reason: String,
    pub restricted_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiPrivilegeRevoked {
    pub tenant_id: String,
    pub entity_id: String,
    pub revoked_by: String,
    pub revoked_permissions: Vec<String>,
    pub reason: String,
    pub revoked_at: DateTime<Utc>,
}
