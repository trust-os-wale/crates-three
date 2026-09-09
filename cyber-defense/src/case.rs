use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "case_status", rename_all = "lowercase")]
pub enum CaseStatus {
    Open,
    Investigating,
    Resolved,
    Closed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityCase {
    pub id: Uuid,
    pub tenant_id: String,
    pub case_number: String,
    pub title: String,
    pub description: String,
    pub status: CaseStatus,
    pub priority: String,
    pub owner_id: Option<String>,
    pub assigned_to: Option<String>,
    pub related_threat_ids: Vec<String>,
    pub related_incident_ids: Vec<String>,
    pub related_vulnerability_ids: Vec<String>,
    pub related_asset_ids: Vec<String>,
    pub related_identity_ids: Vec<String>,
    pub related_evidence_ids: Vec<String>,
    pub related_policy_ids: Vec<String>,
    pub related_control_ids: Vec<String>,
    pub trust_score_impact: Option<f64>,
    pub risk_score_impact: Option<f64>,
    pub compliance_impact: Option<String>,
    pub ai_summary: Option<String>,
    pub resolution: Option<String>,
    pub lessons_learned: Option<String>,
    pub closed_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaseNote {
    pub id: Uuid,
    pub case_id: Uuid,
    pub tenant_id: String,
    pub author_id: String,
    pub content: String,
    pub note_type: String,
    pub is_internal: bool,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateCaseRequest {
    pub tenant_id: String,
    pub title: String,
    pub description: String,
    pub priority: String,
    pub owner_id: Option<String>,
    pub related_threat_ids: Vec<String>,
    pub related_incident_ids: Vec<String>,
    pub related_vulnerability_ids: Vec<String>,
    pub related_asset_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaseResponse {
    pub id: String,
    pub tenant_id: String,
    pub case_number: String,
    pub title: String,
    pub description: String,
    pub status: String,
    pub priority: String,
    pub owner_id: Option<String>,
    pub related_threat_ids: Vec<String>,
    pub related_incident_ids: Vec<String>,
    pub ai_summary: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddNoteRequest {
    pub author_id: String,
    pub content: String,
    pub note_type: String,
    pub is_internal: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaseStats {
    pub total: i64,
    pub open: i64,
    pub investigating: i64,
    pub resolved: i64,
    pub closed: i64,
    pub by_priority: Vec<(String, i64)>,
}
