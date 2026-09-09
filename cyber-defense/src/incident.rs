use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "incident_severity", rename_all = "lowercase")]
pub enum IncidentSeverity {
    Critical,
    High,
    Medium,
    Low,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "incident_status", rename_all = "lowercase")]
pub enum IncidentStatus {
    Open,
    Investigating,
    Contained,
    Eradicated,
    Recovering,
    Closed,
    Reopened,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "incident_priority", rename_all = "lowercase")]
pub enum IncidentPriority {
    P1,
    P2,
    P3,
    P4,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Incident {
    pub id: Uuid,
    pub tenant_id: String,
    pub title: String,
    pub description: String,
    pub severity: IncidentSeverity,
    pub priority: IncidentPriority,
    pub status: IncidentStatus,
    pub owner_id: Option<String>,
    pub assigned_to: Option<String>,
    pub related_threat_ids: Vec<String>,
    pub related_asset_ids: Vec<String>,
    pub related_identity_ids: Vec<String>,
    pub related_vulnerability_ids: Vec<String>,
    pub related_evidence_ids: Vec<String>,
    pub related_policy_ids: Vec<String>,
    pub ai_summary: Option<String>,
    pub ai_recommendations: Option<String>,
    pub resolution: Option<String>,
    pub root_cause: Option<String>,
    pub lessons_learned: Option<String>,
    pub sla_deadline: Option<DateTime<Utc>>,
    pub contained_at: Option<DateTime<Utc>>,
    pub eradicated_at: Option<DateTime<Utc>>,
    pub recovered_at: Option<DateTime<Utc>>,
    pub closed_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncidentTimeline {
    pub id: Uuid,
    pub incident_id: Uuid,
    pub tenant_id: String,
    pub event_type: String,
    pub description: String,
    pub actor_id: String,
    pub actor_type: String,
    pub metadata: Option<serde_json::Value>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateIncidentRequest {
    pub tenant_id: String,
    pub title: String,
    pub description: String,
    pub severity: IncidentSeverity,
    pub priority: IncidentPriority,
    pub owner_id: Option<String>,
    pub related_threat_ids: Vec<String>,
    pub related_asset_ids: Vec<String>,
    pub related_identity_ids: Vec<String>,
    pub related_vulnerability_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncidentResponse {
    pub id: String,
    pub tenant_id: String,
    pub title: String,
    pub description: String,
    pub severity: String,
    pub priority: String,
    pub status: String,
    pub owner_id: Option<String>,
    pub assigned_to: Option<String>,
    pub related_threat_ids: Vec<String>,
    pub related_asset_ids: Vec<String>,
    pub ai_summary: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncidentStats {
    pub total: i64,
    pub open: i64,
    pub investigating: i64,
    pub contained: i64,
    pub closed: i64,
    pub critical: i64,
    pub high: i64,
    pub medium: i64,
    pub low: i64,
    pub avg_resolution_hours: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddTimelineEntryRequest {
    pub event_type: String,
    pub description: String,
    pub actor_id: String,
    pub actor_type: String,
    pub metadata: Option<serde_json::Value>,
}
