use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ============================================
// TENANT
// ============================================

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Tenant {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub region: String,
    pub status: String,
    pub encryption_key_id: String,
    pub settings: serde_json::Value,
    pub limits: serde_json::Value,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub activated_at: Option<DateTime<Utc>>,
    pub deleted_at: Option<DateTime<Utc>>,
}

// ============================================
// USER
// ============================================

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct User {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub username: String,
    pub email: String,
    pub password_hash: String,
    pub active: bool,
    pub mfa_enabled: bool,
    pub mfa_secret: Option<String>,
    pub mfa_method: Option<String>,
    pub last_login: Option<DateTime<Utc>>,
    pub login_count: Option<i32>,
    pub failed_login_count: Option<i32>,
    pub locked_until: Option<DateTime<Utc>>,
    pub password_changed_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub deleted_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateUser {
    pub tenant_id: Uuid,
    pub username: String,
    pub email: String,
    pub password_hash: String,
    pub mfa_secret: Option<String>,
}

// ============================================
// EVIDENCE
// ============================================

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Evidence {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub evidence_type: String,
    pub source: String,
    pub hash: String,
    pub signature: Option<String>,
    pub validation_status: String,
    pub metadata: serde_json::Value,
    pub storage_path: Option<String>,
    pub storage_bucket: Option<String>,
    pub content_type: Option<String>,
    pub size_bytes: i64,
    pub checksum: Option<String>,
    pub ingested_at: DateTime<Utc>,
    pub validated_at: Option<DateTime<Utc>>,
    pub expires_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

// ============================================
// CONTROL
// ============================================

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Control {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub control_id: String,
    pub control_type: String,
    pub framework: String,
    pub section: Option<String>,
    pub severity: String,
    pub active: bool,
    pub automated: Option<bool>,
    pub testing_frequency_days: Option<i32>,
    pub last_tested_at: Option<DateTime<Utc>>,
    pub next_test_due: Option<DateTime<Utc>>,
    pub metadata: serde_json::Value,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

// ============================================
// RISK
// ============================================

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Risk {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub title: String,
    pub description: Option<String>,
    pub source_type: String,
    pub source_id: Option<String>,
    pub likelihood: f64,
    pub impact: f64,
    pub risk_score: f64,
    pub risk_level: String,
    pub status: String,
    pub owner_id: Option<Uuid>,
    pub due_date: Option<DateTime<Utc>>,
    pub mitigation_plan: Option<String>,
    pub residual_risk_score: Option<f64>,
    pub affected_resources: serde_json::Value,
    pub metadata: serde_json::Value,
    pub detected_at: DateTime<Utc>,
    pub acknowledged_at: Option<DateTime<Utc>>,
    pub remediated_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

// ============================================
// TRUST SCORE
// ============================================

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct TrustScore {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub overall_score: f64,
    pub compliance_component: f64,
    pub risk_component: f64,
    pub evidence_quality_component: f64,
    pub governance_component: f64,
    pub threat_component: f64,
    pub vendor_component: f64,
    pub trend: String,
    pub dimensions: serde_json::Value,
    pub computed_at: DateTime<Utc>,
    pub valid_until: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

// ============================================
// WORKFLOW
// ============================================

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Workflow {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub name: String,
    pub workflow_type: String,
    pub status: String,
    pub trigger_event: Option<String>,
    pub trigger_source_id: Option<String>,
    pub input: serde_json::Value,
    pub output: serde_json::Value,
    pub error_message: Option<String>,
    pub retry_count: Option<i32>,
    pub max_retries: Option<i32>,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

// ============================================
// AUDIT RECORD
// ============================================

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct AuditRecord {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub action_type: String,
    pub actor: String,
    pub actor_type: Option<String>,
    pub resource_type: String,
    pub resource_id: String,
    pub changes: serde_json::Value,
    pub previous_state: Option<serde_json::Value>,
    pub new_state: Option<serde_json::Value>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub correlation_id: Option<String>,
    pub signature: Option<String>,
    pub created_at: DateTime<Utc>,
}

// ============================================
// NOTIFICATION
// ============================================

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Notification {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub user_id: Option<Uuid>,
    pub notification_type: String,
    pub title: String,
    pub message: Option<String>,
    pub severity: Option<String>,
    pub read: Option<bool>,
    pub action_url: Option<String>,
    pub metadata: serde_json::Value,
    pub created_at: DateTime<Utc>,
    pub read_at: Option<DateTime<Utc>>,
}

// ============================================
// EVENT
// ============================================

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Event {
    pub id: Uuid,
    pub event_type: String,
    pub tenant_id: Uuid,
    pub aggregate_id: String,
    pub aggregate_type: String,
    pub correlation_id: Option<String>,
    pub causation_id: Option<String>,
    pub data: serde_json::Value,
    pub metadata: serde_json::Value,
    pub version: i32,
    pub status: String,
    pub published_at: Option<DateTime<Utc>>,
    pub processed_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

// ============================================
// INTEGRATION
// ============================================

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Integration {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub name: String,
    pub integration_type: String,
    pub provider: String,
    pub config: serde_json::Value,
    pub credentials: serde_json::Value,
    pub status: String,
    pub last_sync_at: Option<DateTime<Utc>>,
    pub last_error: Option<String>,
    pub sync_frequency_minutes: Option<i32>,
    pub enabled: Option<bool>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}
