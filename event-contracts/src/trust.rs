use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

pub const EVENT_TRUST_SCORE_COMPUTED: &str = "trust.score.computed";
pub const EVENT_TRUST_PROPAGATED: &str = "trust.propagated";
pub const EVENT_TRUST_THRESHOLD_BREACHED: &str = "trust.threshold.breached";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustScoreComputed {
    pub tenant_id: String,
    pub overall_score: f64,
    pub compliance_component: f64,
    pub risk_component: f64,
    pub evidence_quality: f64,
    pub governance_component: f64,
    pub trend: String,
    pub computed_at: DateTime<Utc>,
    pub valid_until: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustPropagated {
    pub tenant_id: String,
    pub entity_id: String,
    pub entity_type: String,
    pub network_trust_score: f64,
    pub propagated_nodes: u32,
    pub propagated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustThresholdBreached {
    pub tenant_id: String,
    pub current_score: f64,
    pub threshold: f64,
    pub breach_direction: String,
    pub breached_at: DateTime<Utc>,
}
