use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

pub const EVENT_EVIDENCE_INGESTED: &str = "compliance.evidence.ingested";
pub const EVENT_EVIDENCE_VALIDATED: &str = "compliance.evidence.validated";
pub const EVENT_CONTROL_EVALUATED: &str = "compliance.control.evaluated";
pub const EVENT_FRAMEWORK_ASSESSED: &str = "compliance.framework.assessed";
pub const EVENT_REMEDIATION_CREATED: &str = "compliance.remediation.created";
pub const EVENT_REMEDIATION_COMPLETED: &str = "compliance.remediation.completed";
pub const EVENT_COMPLIANCE_CONTROL_FAILED: &str = "compliance.control_failed";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceIngested {
    pub tenant_id: String,
    pub evidence_id: String,
    pub control_id: String,
    pub source: String,
    pub evidence_type: String,
    pub hash: String,
    pub size_bytes: u64,
    pub ingested_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceValidated {
    pub tenant_id: String,
    pub evidence_id: String,
    pub valid: bool,
    pub confidence_score: f64,
    pub validation_method: String,
    pub validated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlEvaluated {
    pub tenant_id: String,
    pub control_id: String,
    pub framework_id: String,
    pub status: String,
    pub score: f64,
    pub evidence_count: u32,
    pub issues: Vec<String>,
    pub evaluated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FrameworkAssessed {
    pub tenant_id: String,
    pub framework_id: String,
    pub overall_score: f64,
    pub total_controls: u32,
    pub compliant: u32,
    pub non_compliant: u32,
    pub assessed_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemediationCreated {
    pub tenant_id: String,
    pub remediation_id: String,
    pub control_id: String,
    pub severity: String,
    pub assigned_to: String,
    pub due_date: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemediationCompleted {
    pub tenant_id: String,
    pub remediation_id: String,
    pub control_id: String,
    pub completed_by: String,
    pub completed_at: DateTime<Utc>,
}
