use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityPosture {
    pub tenant_id: String,
    pub overall_score: f64,
    pub threat_exposure: f64,
    pub vulnerability_score: f64,
    pub incident_score: f64,
    pub identity_risk: f64,
    pub control_health: f64,
    pub security_drift: f64,
    pub cloud_exposure: f64,
    pub policy_violations: i64,
    pub response_status: f64,
    pub internet_facing_assets: i64,
    pub critical_vulnerabilities: i64,
    pub open_incidents: i64,
    pub mean_time_to_respond_hours: Option<f64>,
    pub calculated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostureTrend {
    pub date: String,
    pub score: f64,
    pub threat_exposure: f64,
    pub vulnerability_score: f64,
    pub incident_score: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostureBreakdown {
    pub category: String,
    pub score: f64,
    pub weight: f64,
    pub findings: Vec<PostureFinding>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostureFinding {
    pub finding_type: String,
    pub severity: String,
    pub description: String,
    pub resource_id: Option<String>,
    pub resource_type: Option<String>,
    pub recommendation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CalculatePostureRequest {
    pub tenant_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostureResponse {
    pub tenant_id: String,
    pub overall_score: f64,
    pub threat_exposure: f64,
    pub vulnerability_score: f64,
    pub incident_score: f64,
    pub identity_risk: f64,
    pub control_health: f64,
    pub security_drift: f64,
    pub cloud_exposure: f64,
    pub policy_violations: i64,
    pub internet_facing_assets: i64,
    pub critical_vulnerabilities: i64,
    pub open_incidents: i64,
    pub calculated_at: String,
}
