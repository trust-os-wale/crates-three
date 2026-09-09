use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

pub const EVENT_RISK_CALCULATED: &str = "risk.calculated";
pub const EVENT_RISK_PROPAGATED: &str = "risk.propagated";
pub const EVENT_RISK_FORECASTED: &str = "risk.forecasted";
pub const EVENT_RISK_ACCEPTED: &str = "risk.accepted";
pub const EVENT_RISK_MITIGATED: &str = "risk.mitigated";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskCalculated {
    pub tenant_id: String,
    pub risk_id: String,
    pub source_type: String,
    pub source_id: String,
    pub likelihood: f64,
    pub impact: f64,
    pub risk_score: f64,
    pub risk_level: String,
    pub affected_assets: Vec<String>,
    pub calculated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskPropagated {
    pub tenant_id: String,
    pub source_risk_id: String,
    pub affected_nodes: Vec<RiskAffectedNode>,
    pub total_blast_radius: f64,
    pub propagated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskAffectedNode {
    pub node_id: String,
    pub node_type: String,
    pub propagated_risk: f64,
    pub distance_from_source: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskForecasted {
    pub tenant_id: String,
    pub scenario: String,
    pub forecast_points: Vec<RiskForecastPoint>,
    pub confidence_interval: f64,
    pub forecasted_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskForecastPoint {
    pub date: String,
    pub predicted_score: f64,
    pub lower_bound: f64,
    pub upper_bound: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskAccepted {
    pub tenant_id: String,
    pub risk_id: String,
    pub accepted_by: String,
    pub justification: String,
    pub accepted_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskMitigated {
    pub tenant_id: String,
    pub risk_id: String,
    pub mitigation_action: String,
    pub mitigated_by: String,
    pub residual_risk: f64,
    pub mitigated_at: DateTime<Utc>,
}
