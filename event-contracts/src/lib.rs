pub mod ai;
pub mod audit;
pub mod compliance;
pub mod defense;
pub mod governance;
pub mod identity;
pub mod integration;
pub mod notification;
pub mod policy;
pub mod regulatory;
pub mod report;
pub mod risk;
pub mod schema;
pub mod security;
pub mod telemetry;
pub mod tenant;
pub mod trust;
pub mod workflow;

pub use ai::*;
pub use audit::*;
pub use compliance::*;
pub use defense::*;
pub use governance::*;
pub use identity::*;
pub use integration::*;
pub use notification::*;
pub use policy::*;
pub use regulatory::*;
pub use report::*;
pub use risk::*;
pub use schema::*;
pub use security::*;
pub use telemetry::*;
pub use tenant::*;
pub use trust::*;
pub use workflow::*;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventEnvelope<T: Serialize> {
    pub event_id: String,
    pub event_type: String,
    pub event_version: u32,
    pub tenant_id: String,
    pub aggregate_id: String,
    pub correlation_id: String,
    pub causation_id: String,
    pub source_service: String,
    pub occurred_at: DateTime<Utc>,
    pub published_at: DateTime<Utc>,
    pub data: T,
    pub metadata: std::collections::HashMap<String, String>,
    pub signature: Option<String>,
}

impl<T: Serialize> EventEnvelope<T> {
    pub fn new(
        event_type: &str,
        tenant_id: &str,
        aggregate_id: &str,
        correlation_id: &str,
        source_service: &str,
        data: T,
    ) -> Self {
        let now = Utc::now();
        Self {
            event_id: Uuid::new_v4().to_string(),
            event_type: event_type.to_string(),
            event_version: 1,
            tenant_id: tenant_id.to_string(),
            aggregate_id: aggregate_id.to_string(),
            correlation_id: correlation_id.to_string(),
            causation_id: Uuid::new_v4().to_string(),
            source_service: source_service.to_string(),
            occurred_at: now,
            published_at: now,
            data,
            metadata: std::collections::HashMap::new(),
            signature: None,
        }
    }

    pub fn with_version(mut self, version: u32) -> Self {
        self.event_version = version;
        self
    }

    pub fn with_metadata(mut self, key: &str, value: &str) -> Self {
        self.metadata.insert(key.to_string(), value.to_string());
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum EventType {
    // Tenant events
    TenantCreated,
    TenantMemberAdded,
    TenantMemberRemoved,

    // Identity events
    UserAuthenticated,
    UserRegistered,
    MfaChallenged,
    MfaVerified,
    SessionCreated,
    SessionRevoked,
    CredentialRegistered,

    // Trust events
    TrustScoreComputed,
    TrustPropagated,
    TrustThresholdBreached,

    // Risk events
    RiskCalculated,
    RiskPropagated,
    RiskForecasted,
    RiskAccepted,
    RiskMitigated,

    // Compliance events
    EvidenceIngested,
    EvidenceValidated,
    ControlEvaluated,
    ComplianceControlFailed,
    FrameworkAssessed,
    RemediationCreated,
    RemediationCompleted,

    // Audit events
    AuditRecorded,
    AuditChainVerified,
    AuditAnomalyDetected,

    // Governance events
    GovernanceScoreComputed,
    GovernanceDriftDetected,
    GovernanceFrameworkUpdated,
    GovernanceControlEvaluated,

    // Security events
    SecurityAlertCreated,
    SecurityIncidentCreated,

    // Policy events
    PolicyEvaluated,
    PolicyDenied,

    // Workflow events
    WorkflowStarted,
    WorkflowCompleted,
    WorkflowFailed,

    // AI events
    AiInferenceCreated,
    AiRecommendationCreated,
    AiActionApproved,
    AiActionRejected,
    AiActionExecuted,
    AiActionVerified,

    // Telemetry events
    TelemetryReceived,

    // Integration events
    IntegrationConnected,
    IntegrationFailed,

    // Report events
    ReportGenerated,

    // Notification events
    NotificationSent,
    NotificationFailed,
    AlertTriggered,
    EscalationRaised,

    // Defense events
    AnomalyDetected,
    ThreatBlocked,
    PolicyViolation,
    RuntimeVerified,

    // Regulatory events
    RegulationPublished,
    RegulationUpdated,
    RegulationSuperseded,
    RequirementChanged,
    ApplicabilityEvaluated,
    ApplicabilityChanged,
    ControlMappingCreated,
    ComplianceAssessmentCompleted,
    ComplianceStatusChanged,
    EvidenceExpired,
    EvidenceUpdated,
    ComplianceFindingCreated,
    RiskExposureChanged,
    PolicyImpactDetected,
    RemediationRequired,
    RegulatoryRemediationCompleted,
    ComplianceReverified,
    TrustImpactChanged,
}

impl EventType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::TenantCreated => EVENT_TENANT_CREATED,
            Self::TenantMemberAdded => EVENT_TENANT_MEMBER_ADDED,
            Self::TenantMemberRemoved => EVENT_TENANT_MEMBER_REMOVED,
            Self::UserAuthenticated => EVENT_USER_AUTHENTICATED,
            Self::UserRegistered => EVENT_USER_REGISTERED,
            Self::MfaChallenged => EVENT_MFA_CHALLENGED,
            Self::MfaVerified => EVENT_MFA_VERIFIED,
            Self::SessionCreated => EVENT_SESSION_CREATED,
            Self::SessionRevoked => EVENT_SESSION_REVOKED,
            Self::CredentialRegistered => EVENT_CREDENTIAL_REGISTERED,
            Self::TrustScoreComputed => EVENT_TRUST_SCORE_COMPUTED,
            Self::TrustPropagated => EVENT_TRUST_PROPAGATED,
            Self::TrustThresholdBreached => EVENT_TRUST_THRESHOLD_BREACHED,
            Self::RiskCalculated => EVENT_RISK_CALCULATED,
            Self::RiskPropagated => EVENT_RISK_PROPAGATED,
            Self::RiskForecasted => EVENT_RISK_FORECASTED,
            Self::RiskAccepted => EVENT_RISK_ACCEPTED,
            Self::RiskMitigated => EVENT_RISK_MITIGATED,
            Self::EvidenceIngested => EVENT_EVIDENCE_INGESTED,
            Self::EvidenceValidated => EVENT_EVIDENCE_VALIDATED,
            Self::ControlEvaluated => EVENT_CONTROL_EVALUATED,
            Self::ComplianceControlFailed => EVENT_COMPLIANCE_CONTROL_FAILED,
            Self::FrameworkAssessed => EVENT_FRAMEWORK_ASSESSED,
            Self::RemediationCreated => EVENT_REMEDIATION_CREATED,
            Self::RemediationCompleted => EVENT_REMEDIATION_COMPLETED,
            Self::AuditRecorded => EVENT_AUDIT_RECORDED,
            Self::AuditChainVerified => EVENT_AUDIT_CHAIN_VERIFIED,
            Self::AuditAnomalyDetected => EVENT_AUDIT_ANOMALY_DETECTED,
            Self::GovernanceScoreComputed => EVENT_GOVERNANCE_SCORE_COMPUTED,
            Self::GovernanceDriftDetected => EVENT_GOVERNANCE_DRIFT_DETECTED,
            Self::GovernanceFrameworkUpdated => EVENT_GOVERNANCE_FRAMEWORK_UPDATED,
            Self::GovernanceControlEvaluated => EVENT_GOVERNANCE_CONTROL_EVALUATED,
            Self::SecurityAlertCreated => EVENT_SECURITY_ALERT_CREATED,
            Self::SecurityIncidentCreated => EVENT_SECURITY_INCIDENT_CREATED,
            Self::PolicyEvaluated => EVENT_POLICY_EVALUATED,
            Self::PolicyDenied => EVENT_POLICY_DENIED,
            Self::WorkflowStarted => EVENT_WORKFLOW_STARTED,
            Self::WorkflowCompleted => EVENT_WORKFLOW_COMPLETED,
            Self::WorkflowFailed => EVENT_WORKFLOW_FAILED,
            Self::AiInferenceCreated => EVENT_AI_INFERENCE_CREATED,
            Self::AiRecommendationCreated => EVENT_AI_RECOMMENDATION_CREATED,
            Self::AiActionApproved => EVENT_AI_ACTION_APPROVED,
            Self::AiActionRejected => EVENT_AI_ACTION_REJECTED,
            Self::AiActionExecuted => EVENT_AI_ACTION_EXECUTED,
            Self::AiActionVerified => EVENT_AI_ACTION_VERIFIED,
            Self::TelemetryReceived => EVENT_TELEMETRY_RECEIVED,
            Self::IntegrationConnected => EVENT_INTEGRATION_CONNECTED,
            Self::IntegrationFailed => EVENT_INTEGRATION_FAILED,
            Self::ReportGenerated => EVENT_REPORT_GENERATED,
            Self::NotificationSent => EVENT_NOTIFICATION_SENT,
            Self::NotificationFailed => EVENT_NOTIFICATION_FAILED,
            Self::AlertTriggered => EVENT_ALERT_TRIGGERED,
            Self::EscalationRaised => EVENT_ESCALATION_RAISED,
            Self::AnomalyDetected => EVENT_ANOMALY_DETECTED,
            Self::ThreatBlocked => EVENT_THREAT_BLOCKED,
            Self::PolicyViolation => EVENT_POLICY_VIOLATION,
            Self::RuntimeVerified => EVENT_RUNTIME_VERIFIED,
            Self::RegulationPublished => EVENT_REGULATION_PUBLISHED,
            Self::RegulationUpdated => EVENT_REGULATION_UPDATED,
            Self::RegulationSuperseded => EVENT_REGULATION_SUPERSEDED,
            Self::RequirementChanged => EVENT_REQUIREMENT_CHANGED,
            Self::ApplicabilityEvaluated => EVENT_APPLICABILITY_EVALUATED,
            Self::ApplicabilityChanged => EVENT_APPLICABILITY_CHANGED,
            Self::ControlMappingCreated => EVENT_CONTROL_MAPPING_CREATED,
            Self::ComplianceAssessmentCompleted => EVENT_COMPLIANCE_ASSESSMENT_COMPLETED,
            Self::ComplianceStatusChanged => EVENT_COMPLIANCE_STATUS_CHANGED,
            Self::EvidenceExpired => EVENT_EVIDENCE_EXPIRED,
            Self::EvidenceUpdated => EVENT_EVIDENCE_UPDATED,
            Self::ComplianceFindingCreated => EVENT_COMPLIANCE_FINDING_CREATED,
            Self::RiskExposureChanged => EVENT_RISK_EXPOSURE_CHANGED,
            Self::PolicyImpactDetected => EVENT_POLICY_IMPACT_DETECTED,
            Self::RemediationRequired => EVENT_REMEDIATION_REQUIRED,
            Self::RegulatoryRemediationCompleted => EVENT_REGULATORY_REMEDIATION_COMPLETED,
            Self::ComplianceReverified => EVENT_COMPLIANCE_REVERIFIED,
            Self::TrustImpactChanged => EVENT_TRUST_IMPACT_CHANGED,
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            EVENT_TENANT_CREATED => Some(Self::TenantCreated),
            EVENT_TENANT_MEMBER_ADDED => Some(Self::TenantMemberAdded),
            EVENT_TENANT_MEMBER_REMOVED => Some(Self::TenantMemberRemoved),
            EVENT_USER_AUTHENTICATED => Some(Self::UserAuthenticated),
            EVENT_USER_REGISTERED => Some(Self::UserRegistered),
            EVENT_MFA_CHALLENGED => Some(Self::MfaChallenged),
            EVENT_MFA_VERIFIED => Some(Self::MfaVerified),
            EVENT_SESSION_CREATED => Some(Self::SessionCreated),
            EVENT_SESSION_REVOKED => Some(Self::SessionRevoked),
            EVENT_CREDENTIAL_REGISTERED => Some(Self::CredentialRegistered),
            EVENT_TRUST_SCORE_COMPUTED => Some(Self::TrustScoreComputed),
            EVENT_TRUST_PROPAGATED => Some(Self::TrustPropagated),
            EVENT_TRUST_THRESHOLD_BREACHED => Some(Self::TrustThresholdBreached),
            EVENT_RISK_CALCULATED => Some(Self::RiskCalculated),
            EVENT_RISK_PROPAGATED => Some(Self::RiskPropagated),
            EVENT_RISK_FORECASTED => Some(Self::RiskForecasted),
            EVENT_RISK_ACCEPTED => Some(Self::RiskAccepted),
            EVENT_RISK_MITIGATED => Some(Self::RiskMitigated),
            EVENT_EVIDENCE_INGESTED => Some(Self::EvidenceIngested),
            EVENT_EVIDENCE_VALIDATED => Some(Self::EvidenceValidated),
            EVENT_CONTROL_EVALUATED => Some(Self::ControlEvaluated),
            EVENT_COMPLIANCE_CONTROL_FAILED => Some(Self::ComplianceControlFailed),
            EVENT_FRAMEWORK_ASSESSED => Some(Self::FrameworkAssessed),
            EVENT_REMEDIATION_CREATED => Some(Self::RemediationCreated),
            EVENT_REMEDIATION_COMPLETED => Some(Self::RemediationCompleted),
            EVENT_AUDIT_RECORDED => Some(Self::AuditRecorded),
            EVENT_AUDIT_CHAIN_VERIFIED => Some(Self::AuditChainVerified),
            EVENT_AUDIT_ANOMALY_DETECTED => Some(Self::AuditAnomalyDetected),
            EVENT_GOVERNANCE_SCORE_COMPUTED => Some(Self::GovernanceScoreComputed),
            EVENT_GOVERNANCE_DRIFT_DETECTED => Some(Self::GovernanceDriftDetected),
            EVENT_GOVERNANCE_FRAMEWORK_UPDATED => Some(Self::GovernanceFrameworkUpdated),
            EVENT_GOVERNANCE_CONTROL_EVALUATED => Some(Self::GovernanceControlEvaluated),
            EVENT_SECURITY_ALERT_CREATED => Some(Self::SecurityAlertCreated),
            EVENT_SECURITY_INCIDENT_CREATED => Some(Self::SecurityIncidentCreated),
            EVENT_POLICY_EVALUATED => Some(Self::PolicyEvaluated),
            EVENT_POLICY_DENIED => Some(Self::PolicyDenied),
            EVENT_WORKFLOW_STARTED => Some(Self::WorkflowStarted),
            EVENT_WORKFLOW_COMPLETED => Some(Self::WorkflowCompleted),
            EVENT_WORKFLOW_FAILED => Some(Self::WorkflowFailed),
            EVENT_AI_INFERENCE_CREATED => Some(Self::AiInferenceCreated),
            EVENT_AI_RECOMMENDATION_CREATED => Some(Self::AiRecommendationCreated),
            EVENT_AI_ACTION_APPROVED => Some(Self::AiActionApproved),
            EVENT_AI_ACTION_REJECTED => Some(Self::AiActionRejected),
            EVENT_AI_ACTION_EXECUTED => Some(Self::AiActionExecuted),
            EVENT_AI_ACTION_VERIFIED => Some(Self::AiActionVerified),
            EVENT_TELEMETRY_RECEIVED => Some(Self::TelemetryReceived),
            EVENT_INTEGRATION_CONNECTED => Some(Self::IntegrationConnected),
            EVENT_INTEGRATION_FAILED => Some(Self::IntegrationFailed),
            EVENT_REPORT_GENERATED => Some(Self::ReportGenerated),
            EVENT_NOTIFICATION_SENT => Some(Self::NotificationSent),
            EVENT_NOTIFICATION_FAILED => Some(Self::NotificationFailed),
            EVENT_ALERT_TRIGGERED => Some(Self::AlertTriggered),
            EVENT_ESCALATION_RAISED => Some(Self::EscalationRaised),
            EVENT_ANOMALY_DETECTED => Some(Self::AnomalyDetected),
            EVENT_THREAT_BLOCKED => Some(Self::ThreatBlocked),
            EVENT_POLICY_VIOLATION => Some(Self::PolicyViolation),
            EVENT_RUNTIME_VERIFIED => Some(Self::RuntimeVerified),
            EVENT_REGULATION_PUBLISHED => Some(Self::RegulationPublished),
            EVENT_REGULATION_UPDATED => Some(Self::RegulationUpdated),
            EVENT_REGULATION_SUPERSEDED => Some(Self::RegulationSuperseded),
            EVENT_REQUIREMENT_CHANGED => Some(Self::RequirementChanged),
            EVENT_APPLICABILITY_EVALUATED => Some(Self::ApplicabilityEvaluated),
            EVENT_APPLICABILITY_CHANGED => Some(Self::ApplicabilityChanged),
            EVENT_CONTROL_MAPPING_CREATED => Some(Self::ControlMappingCreated),
            EVENT_COMPLIANCE_ASSESSMENT_COMPLETED => Some(Self::ComplianceAssessmentCompleted),
            EVENT_COMPLIANCE_STATUS_CHANGED => Some(Self::ComplianceStatusChanged),
            EVENT_EVIDENCE_EXPIRED => Some(Self::EvidenceExpired),
            EVENT_EVIDENCE_UPDATED => Some(Self::EvidenceUpdated),
            EVENT_COMPLIANCE_FINDING_CREATED => Some(Self::ComplianceFindingCreated),
            EVENT_RISK_EXPOSURE_CHANGED => Some(Self::RiskExposureChanged),
            EVENT_POLICY_IMPACT_DETECTED => Some(Self::PolicyImpactDetected),
            EVENT_REMEDIATION_REQUIRED => Some(Self::RemediationRequired),
            EVENT_REGULATORY_REMEDIATION_COMPLETED => Some(Self::RegulatoryRemediationCompleted),
            EVENT_COMPLIANCE_REVERIFIED => Some(Self::ComplianceReverified),
            EVENT_TRUST_IMPACT_CHANGED => Some(Self::TrustImpactChanged),
            _ => None,
        }
    }
}
