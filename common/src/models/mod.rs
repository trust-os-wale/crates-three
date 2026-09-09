use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

// ============================================
// TENANT MODELS
// ============================================

/// Represents a tenant in the multi-tenant system
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Tenant {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub region: String,
    pub status: TenantStatus,
    pub encryption_key_id: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum TenantStatus {
    Active,
    Suspended,
    Archived,
    PendingActivation,
}

impl Tenant {
    pub fn new(name: String, region: String, encryption_key_id: String) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4().to_string(),
            name,
            description: None,
            region,
            status: TenantStatus::PendingActivation,
            encryption_key_id,
            created_at: now,
            updated_at: now,
        }
    }
}

/// Tenant context injected into every request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TenantContext {
    pub tenant_id: String,
    pub user_id: String,
    pub user_name: String,
    pub permissions: Vec<String>,
    pub roles: Vec<String>,
    pub trace_id: String,
    pub correlation_id: String,
    pub request_timestamp: DateTime<Utc>,
}

// ============================================
// USER & IDENTITY MODELS
// ============================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: String,
    pub tenant_id: String,
    pub username: String,
    pub email: String,
    pub active: bool,
    pub mfa_enabled: bool,
    pub mfa_secret: Option<String>,
    pub password_hash: String,
    pub last_login: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceAccount {
    pub id: String,
    pub tenant_id: String,
    pub name: String,
    pub public_key: String,
    pub active: bool,
    pub capabilities: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Role {
    pub id: String,
    pub tenant_id: String,
    pub name: String,
    pub description: Option<String>,
    pub permissions: Vec<Permission>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Permission {
    pub action: String,        // read, write, delete, execute
    pub resource_type: String, // control, evidence, workflow
    pub constraints: Vec<String>,
}

// ============================================
// EVIDENCE MODELS
// ============================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    pub id: String,
    pub tenant_id: String,
    pub evidence_type: String,
    pub source: String,
    pub hash: String,
    pub signature: String,
    pub validation_status: ValidationStatus,
    pub metadata: HashMap<String, serde_json::Value>,
    pub size_bytes: u64,
    pub ingested_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ValidationStatus {
    Valid,
    Invalid,
    Partial,
    Pending,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceValidationResult {
    pub valid: bool,
    pub score: f32,
    pub issues: Vec<String>,
    pub warnings: Vec<String>,
}

// ============================================
// CONTROL & COMPLIANCE MODELS
// ============================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Control {
    pub id: String,
    pub tenant_id: String,
    pub name: String,
    pub description: String,
    pub control_type: ControlType,
    pub framework: String,
    pub severity: SeverityLevel,
    pub active: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ControlType {
    Preventive,
    Detective,
    Corrective,
    Hybrid,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum SeverityLevel {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl SeverityLevel {
    pub fn weight(&self) -> f32 {
        match self {
            SeverityLevel::Critical => 5.0,
            SeverityLevel::High => 4.0,
            SeverityLevel::Medium => 3.0,
            SeverityLevel::Low => 2.0,
            SeverityLevel::Info => 1.0,
        }
    }

    pub fn score(&self) -> u32 {
        match self {
            SeverityLevel::Critical => 100,
            SeverityLevel::High => 80,
            SeverityLevel::Medium => 60,
            SeverityLevel::Low => 40,
            SeverityLevel::Info => 20,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlEvaluation {
    pub id: String,
    pub control_id: String,
    pub tenant_id: String,
    pub status: ComplianceStatus,
    pub score: f32,
    pub evidence_count: i32,
    pub evaluated_at: DateTime<Utc>,
    pub next_evaluation: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ComplianceStatus {
    Compliant,
    NonCompliant,
    PartiallyCompliant,
    Unknown,
    NotApplicable,
}

// ============================================
// RISK MODELS
// ============================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Risk {
    pub id: String,
    pub tenant_id: String,
    pub source_type: String,
    pub source_id: String,
    pub likelihood: f32,
    pub impact: f32,
    pub risk_score: f32,
    pub status: RiskStatus,
    pub affected_resources: Vec<String>,
    pub detected_at: DateTime<Utc>,
    pub acknowledged_at: Option<DateTime<Utc>>,
    pub remediated_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum RiskStatus {
    Active,
    Mitigated,
    Acknowledged,
    Remediated,
    Accepted,
    Monitoring,
}

// ============================================
// TRUST SCORE MODELS
// ============================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustScore {
    pub tenant_id: String,
    pub overall_score: f32,
    pub compliance_component: f32,
    pub risk_component: f32,
    pub evidence_quality_component: f32,
    pub governance_component: f32,
    pub trend: TrustTrend,
    pub computed_at: DateTime<Utc>,
    pub valid_until: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum TrustTrend {
    Improving,
    Degrading,
    Stable,
    Volatile,
}

// ============================================
// WORKFLOW MODELS
// ============================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Workflow {
    pub id: String,
    pub tenant_id: String,
    pub name: String,
    pub workflow_type: String,
    pub status: WorkflowStatus,
    pub trigger_event: String,
    pub trigger_source_id: String,
    pub created_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum WorkflowStatus {
    Created,
    InProgress,
    Completed,
    Failed,
    Cancelled,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemediationAction {
    pub id: String,
    pub tenant_id: String,
    pub control_id: String,
    pub severity: SeverityLevel,
    pub assigned_to: String,
    pub due_date: DateTime<Utc>,
    pub status: RemediationStatus,
    pub created_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum RemediationStatus {
    Open,
    InProgress,
    Completed,
    Overdue,
    Cancelled,
}

// ============================================
// AUDIT MODELS
// ============================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditRecord {
    pub id: String,
    pub tenant_id: String,
    pub action_type: String,
    pub actor: String,
    pub resource_type: String,
    pub resource_id: String,
    pub changes: HashMap<String, String>,
    pub ip_address: String,
    pub user_agent: String,
    pub created_at: DateTime<Utc>,
}

// ============================================
// EVENT MODELS
// ============================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    pub event_id: String,
    pub event_type: String,
    pub tenant_id: String,
    pub aggregate_id: String,
    pub correlation_id: String,
    pub causation_id: String,
    pub occurred_at: DateTime<Utc>,
    pub published_at: DateTime<Utc>,
    pub data: serde_json::Value,
}

// ============================================
// API MODELS
// ============================================

#[derive(Debug, Serialize, Deserialize)]
pub struct ApiResponse<T> {
    pub success: bool,
    pub data: Option<T>,
    pub error: Option<String>,
    pub timestamp: DateTime<Utc>,
    pub correlation_id: String,
}

impl<T> ApiResponse<T> {
    pub fn success(data: T, correlation_id: String) -> Self {
        Self {
            success: true,
            data: Some(data),
            error: None,
            timestamp: Utc::now(),
            correlation_id,
        }
    }

    pub fn error(error: String, correlation_id: String) -> Self {
        Self {
            success: false,
            data: None,
            error: Some(error),
            timestamp: Utc::now(),
            correlation_id,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PaginatedResponse<T> {
    pub items: Vec<T>,
    pub total: i64,
    pub page: i32,
    pub page_size: i32,
    pub total_pages: i32,
}

// ============================================
// PAGINATION
// ============================================

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PaginationParams {
    pub page: Option<i32>,
    pub page_size: Option<i32>,
    pub sort_by: Option<String>,
    pub sort_order: Option<SortOrder>,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub enum SortOrder {
    Asc,
    Desc,
}

impl Default for PaginationParams {
    fn default() -> Self {
        Self {
            page: Some(1),
            page_size: Some(50),
            sort_by: None,
            sort_order: Some(SortOrder::Desc),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_severity_weights() {
        assert_eq!(SeverityLevel::Critical.weight(), 5.0);
        assert_eq!(SeverityLevel::High.weight(), 4.0);
        assert_eq!(SeverityLevel::Low.weight(), 2.0);
    }

    #[test]
    fn test_severity_scores() {
        assert_eq!(SeverityLevel::Critical.score(), 100);
        assert_eq!(SeverityLevel::Info.score(), 20);
    }

    #[test]
    fn test_tenant_creation() {
        let tenant = Tenant::new("Test".into(), "us-east-1".into(), "key-1".into());
        assert_eq!(tenant.name, "Test");
        assert_eq!(tenant.status, TenantStatus::PendingActivation);
    }
}
