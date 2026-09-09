//! Regulatory intelligence event contracts.
//!
//! Events published by the `regulatory-intelligence` and
//! `compliance-as-code` services. All payloads are tenant-scoped and flow
//! through the standard `EventEnvelope<T>`.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

pub const EVENT_REGULATION_PUBLISHED: &str = "regulatory.regulation.published";
pub const EVENT_REGULATION_UPDATED: &str = "regulatory.regulation.updated";
pub const EVENT_REGULATION_SUPERSEDED: &str = "regulatory.regulation.superseded";
pub const EVENT_REQUIREMENT_CHANGED: &str = "regulatory.requirement.changed";
pub const EVENT_APPLICABILITY_EVALUATED: &str = "regulatory.applicability.evaluated";
pub const EVENT_APPLICABILITY_CHANGED: &str = "regulatory.applicability.changed";
pub const EVENT_CONTROL_MAPPING_CREATED: &str = "regulatory.control_mapping.created";
pub const EVENT_COMPLIANCE_ASSESSMENT_COMPLETED: &str = "regulatory.assessment.completed";
pub const EVENT_COMPLIANCE_STATUS_CHANGED: &str = "regulatory.compliance.status_changed";
pub const EVENT_EVIDENCE_EXPIRED: &str = "regulatory.evidence.expired";
pub const EVENT_EVIDENCE_UPDATED: &str = "regulatory.evidence.updated";
pub const EVENT_COMPLIANCE_FINDING_CREATED: &str = "regulatory.compliance.finding_created";
pub const EVENT_RISK_EXPOSURE_CHANGED: &str = "regulatory.risk.exposure_changed";
pub const EVENT_POLICY_IMPACT_DETECTED: &str = "regulatory.policy.impact_detected";
pub const EVENT_REMEDIATION_REQUIRED: &str = "regulatory.remediation.required";
pub const EVENT_REGULATORY_REMEDIATION_COMPLETED: &str = "regulatory.remediation.completed";
pub const EVENT_COMPLIANCE_REVERIFIED: &str = "regulatory.compliance.reverified";
pub const EVENT_TRUST_IMPACT_CHANGED: &str = "regulatory.trust.impact_changed";

/// Emitted when a new regulation version enters force.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegulationPublished {
    pub tenant_id: String,
    pub regulation_id: String,
    pub version_id: String,
    pub version_number: i64,
    pub title: String,
    pub effective_from: Option<DateTime<Utc>>,
    pub source_id: Option<String>,
    pub published_at: DateTime<Utc>,
}

/// Emitted when an existing regulation is amended.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegulationUpdated {
    pub tenant_id: String,
    pub regulation_id: String,
    pub previous_version_id: String,
    pub new_version_id: String,
    pub change_number: String,
    pub updated_at: DateTime<Utc>,
}

/// Emitted when a regulation version is superseded.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegulationSuperseded {
    pub tenant_id: String,
    pub regulation_id: String,
    pub superseded_version_id: String,
    pub superseding_version_id: String,
    pub effective_from: Option<DateTime<Utc>>,
    pub superseded_at: DateTime<Utc>,
}

/// Emitted when a requirement is added, removed, or materially modified.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequirementChanged {
    pub tenant_id: String,
    pub regulation_id: String,
    pub version_id: String,
    pub requirement_id: String,
    pub requirement_code: String,
    pub change: String,
    pub is_mandatory: bool,
    pub changed_at: DateTime<Utc>,
}

/// Emitted when applicability is evaluated for a target.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApplicabilityEvaluated {
    pub tenant_id: String,
    pub organization_id: String,
    pub target_type: String,
    pub target_id: String,
    pub decision: String,
    pub confidence: f64,
    pub review_required: bool,
    pub reason: String,
    pub evaluated_at: DateTime<Utc>,
}

/// Emitted when an applicability decision transitions state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApplicabilityChanged {
    pub tenant_id: String,
    pub organization_id: String,
    pub target_type: String,
    pub target_id: String,
    pub previous_decision: String,
    pub new_decision: String,
    pub changed_at: DateTime<Utc>,
}

/// Emitted when a verified control mapping is created.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlMappingCreated {
    pub tenant_id: String,
    pub mapping_id: String,
    pub mapping_type: String,
    pub source_id: String,
    pub target_id: String,
    pub verification_status: String,
    pub ai_generated: bool,
    pub created_at: DateTime<Utc>,
}

/// Emitted when a compliance assessment run completes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceAssessmentCompleted {
    pub tenant_id: String,
    pub organization_id: String,
    pub assessment_id: String,
    pub framework_id: Option<String>,
    pub regulation_id: Option<String>,
    pub status: String,
    pub overall_score: f64,
    pub assessed_requirements: u32,
    pub assessed_at: DateTime<Utc>,
}

/// Emitted when an organization's compliance status changes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceStatusChanged {
    pub tenant_id: String,
    pub organization_id: String,
    pub assessment_id: String,
    pub previous_status: String,
    pub new_status: String,
    pub changed_at: DateTime<Utc>,
}

/// Emitted when evidence freshness expires for a control/requirement.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceExpired {
    pub tenant_id: String,
    pub evidence_id: String,
    pub control_id: Option<String>,
    pub requirement_id: Option<String>,
    pub expired_at: DateTime<Utc>,
}

/// Emitted when evidence for a control/requirement is updated.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceUpdated {
    pub tenant_id: String,
    pub evidence_id: String,
    pub control_id: Option<String>,
    pub requirement_id: Option<String>,
    pub valid: bool,
    pub updated_at: DateTime<Utc>,
}

/// Emitted when a compliance finding is created.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceFindingCreated {
    pub tenant_id: String,
    pub finding_id: String,
    pub assessment_id: Option<String>,
    pub requirement_id: Option<String>,
    pub severity: String,
    pub title: String,
    pub created_at: DateTime<Utc>,
}

/// Emitted when regulatory risk exposure changes for an organization.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskExposureChanged {
    pub tenant_id: String,
    pub organization_id: String,
    pub previous_exposure: f64,
    pub new_exposure: f64,
    pub reasons: Vec<String>,
    pub changed_at: DateTime<Utc>,
}

/// Emitted when a regulatory change impacts an active policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyImpactDetected {
    pub tenant_id: String,
    pub change_id: String,
    pub policy_id: String,
    pub impact_level: String,
    pub description: String,
    pub detected_at: DateTime<Utc>,
}

/// Emitted when remediation is required to close a gap.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemediationRequired {
    pub tenant_id: String,
    pub remediation_id: String,
    pub finding_id: Option<String>,
    pub requirement_id: Option<String>,
    pub control_id: Option<String>,
    pub priority: String,
    pub approval_required: bool,
    pub due_date: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

/// Emitted when remediation completes and is verified.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegulatoryRemediationCompleted {
    pub tenant_id: String,
    pub remediation_id: String,
    pub requirement_id: Option<String>,
    pub control_id: Option<String>,
    pub verification_result: Option<String>,
    pub completed_at: DateTime<Utc>,
}

/// Emitted when a previously unresolved status is re-verified compliant.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceReverified {
    pub tenant_id: String,
    pub organization_id: String,
    pub assessment_id: String,
    pub requirement_id: Option<String>,
    pub previous_status: String,
    pub new_status: String,
    pub reverified_at: DateTime<Utc>,
}

/// Emitted when a compliance change alters the organization's trust score.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustImpactChanged {
    pub tenant_id: String,
    pub organization_id: String,
    pub assessment_id: String,
    pub impact_delta: f64,
    pub reason: String,
    pub changed_at: DateTime<Utc>,
}
