use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

pub const EVENT_GOVERNANCE_SCORE_COMPUTED: &str = "governance.score.computed";
pub const EVENT_GOVERNANCE_DRIFT_DETECTED: &str = "governance.drift.detected";
pub const EVENT_GOVERNANCE_FRAMEWORK_UPDATED: &str = "governance.framework.updated";
pub const EVENT_GOVERNANCE_CONTROL_EVALUATED: &str = "governance.control.evaluated";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GovernanceScoreComputed {
    pub tenant_id: String,
    pub framework_id: String,
    pub overall_score: f64,
    pub compliance_weight: f64,
    pub risk_weight: f64,
    pub trust_weight: f64,
    pub control_count: u32,
    pub compliant_count: u32,
    pub non_compliant_count: u32,
    pub computed_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GovernanceDriftDetected {
    pub tenant_id: String,
    pub framework_id: String,
    pub drift_score: f64,
    pub drift_events: Vec<DriftEvent>,
    pub detected_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DriftEvent {
    pub control_id: String,
    pub previous_status: String,
    pub current_status: String,
    pub impact_score: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FrameworkUpdated {
    pub tenant_id: String,
    pub framework_id: String,
    pub framework_name: String,
    pub updated_by: String,
    pub changes: Vec<String>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GovernanceControlEvaluated {
    pub tenant_id: String,
    pub control_id: String,
    pub framework_id: String,
    pub status: String,
    pub score: f64,
    pub evidence_count: u32,
    pub evaluated_at: DateTime<Utc>,
}
