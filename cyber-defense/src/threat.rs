use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "threat_severity", rename_all = "lowercase")]
pub enum ThreatSeverity {
    Critical,
    High,
    Medium,
    Low,
    Informational,
}

impl ThreatSeverity {
    pub fn score(&self) -> f64 {
        match self {
            ThreatSeverity::Critical => 1.0,
            ThreatSeverity::High => 0.8,
            ThreatSeverity::Medium => 0.5,
            ThreatSeverity::Low => 0.3,
            ThreatSeverity::Informational => 0.1,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "threat_status", rename_all = "lowercase")]
pub enum ThreatStatus {
    New,
    Investigating,
    Confirmed,
    FalsePositive,
    Resolved,
    Escalated,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "threat_type", rename_all = "lowercase")]
pub enum ThreatType {
    Malware,
    Phishing,
    UnauthorizedAccess,
    DataExfiltration,
    DenialOfService,
    PrivilegeEscalation,
    LateralMovement,
    CommandAndControl,
    CredentialDump,
    SuspiciousNetwork,
    Anomaly,
    PolicyViolation,
    InsiderThreat,
    SupplyChain,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatDetection {
    pub id: Uuid,
    pub tenant_id: String,
    pub threat_type: ThreatType,
    pub severity: ThreatSeverity,
    pub confidence: f64,
    pub status: ThreatStatus,
    pub title: String,
    pub description: String,
    pub source: String,
    pub source_event_id: Option<String>,
    pub affected_asset_id: Option<String>,
    pub affected_asset_type: Option<String>,
    pub affected_identity_id: Option<String>,
    pub mitre_tactic: Option<String>,
    pub mitre_technique: Option<String>,
    pub mitre_id: Option<String>,
    pub indicator_value: Option<String>,
    pub indicator_type: Option<String>,
    pub correlation_id: Option<String>,
    pub risk_score: Option<f64>,
    pub trust_impact: Option<f64>,
    pub detected_at: DateTime<Utc>,
    pub investigated_at: Option<DateTime<Utc>>,
    pub resolved_at: Option<DateTime<Utc>>,
    pub assigned_to: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateThreatRequest {
    pub tenant_id: String,
    pub threat_type: ThreatType,
    pub severity: ThreatSeverity,
    pub confidence: f64,
    pub title: String,
    pub description: String,
    pub source: String,
    pub source_event_id: Option<String>,
    pub affected_asset_id: Option<String>,
    pub affected_asset_type: Option<String>,
    pub affected_identity_id: Option<String>,
    pub mitre_tactic: Option<String>,
    pub mitre_technique: Option<String>,
    pub mitre_id: Option<String>,
    pub indicator_value: Option<String>,
    pub indicator_type: Option<String>,
    pub correlation_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatResponse {
    pub id: String,
    pub tenant_id: String,
    pub threat_type: String,
    pub severity: String,
    pub confidence: f64,
    pub status: String,
    pub title: String,
    pub description: String,
    pub source: String,
    pub affected_asset_id: Option<String>,
    pub affected_identity_id: Option<String>,
    pub mitre_tactic: Option<String>,
    pub mitre_technique: Option<String>,
    pub risk_score: Option<f64>,
    pub detected_at: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatStats {
    pub total: i64,
    pub critical: i64,
    pub high: i64,
    pub medium: i64,
    pub low: i64,
    pub informational: i64,
    pub new_count: i64,
    pub investigating: i64,
    pub confirmed: i64,
    pub false_positive: i64,
    pub resolved: i64,
}
