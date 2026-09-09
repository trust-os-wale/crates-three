use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "response_action_type", rename_all = "lowercase")]
pub enum ResponseActionType {
    RevokeSession,
    DisableIdentity,
    IsolateAsset,
    BlockIndicator,
    ChangePolicy,
    CreateTicket,
    TriggerIntegration,
    InitiateRemediation,
    Notify,
    Escalate,
    Quarantine,
    BlockIp,
    BlockDomain,
    ResetCredentials,
    EnableMfa,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "response_action_status", rename_all = "lowercase")]
pub enum ResponseActionStatus {
    Pending,
    Approved,
    Executing,
    Completed,
    Failed,
    Rejected,
    Cancelled,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "response_playbook_trigger", rename_all = "lowercase")]
pub enum PlaybookTrigger {
    Manual,
    ThreatDetected,
    IncidentCreated,
    VulnerabilityFound,
    PolicyViolation,
    AnomalyDetected,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseAction {
    pub id: Uuid,
    pub tenant_id: String,
    pub action_type: ResponseActionType,
    pub status: ResponseActionStatus,
    pub title: String,
    pub description: String,
    pub threat_id: Option<String>,
    pub incident_id: Option<String>,
    pub vulnerability_id: Option<String>,
    pub asset_id: Option<String>,
    pub identity_id: Option<String>,
    pub indicator_id: Option<String>,
    pub policy_id: Option<String>,
    pub workflow_id: Option<String>,
    pub ai_recommendation: Option<String>,
    pub authorization_required: bool,
    pub authorization_status: Option<String>,
    pub authorized_by: Option<String>,
    pub authorized_at: Option<DateTime<Utc>>,
    pub executed_by: Option<String>,
    pub executed_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub failed_at: Option<DateTime<Utc>>,
    pub error_message: Option<String>,
    pub metadata: Option<serde_json::Value>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponsePlaybook {
    pub id: Uuid,
    pub tenant_id: String,
    pub name: String,
    pub description: String,
    pub trigger: PlaybookTrigger,
    pub trigger_conditions: serde_json::Value,
    pub actions: Vec<PlaybookAction>,
    pub is_active: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlaybookAction {
    pub step: i32,
    pub action_type: ResponseActionType,
    pub parameters: serde_json::Value,
    pub requires_approval: bool,
    pub timeout_seconds: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateActionRequest {
    pub tenant_id: String,
    pub action_type: ResponseActionType,
    pub title: String,
    pub description: String,
    pub threat_id: Option<String>,
    pub incident_id: Option<String>,
    pub vulnerability_id: Option<String>,
    pub asset_id: Option<String>,
    pub identity_id: Option<String>,
    pub indicator_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionResponse {
    pub id: String,
    pub tenant_id: String,
    pub action_type: String,
    pub status: String,
    pub title: String,
    pub description: String,
    pub authorization_required: bool,
    pub authorization_status: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizeActionRequest {
    pub authorized_by: String,
    pub approved: bool,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseStats {
    pub total_actions: i64,
    pub pending: i64,
    pub approved: i64,
    pub executing: i64,
    pub completed: i64,
    pub failed: i64,
    pub rejected: i64,
    pub by_type: Vec<(String, i64)>,
}
