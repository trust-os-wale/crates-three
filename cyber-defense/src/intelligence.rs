use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "indicator_type", rename_all = "lowercase")]
pub enum IndicatorType {
    IpAddress,
    Domain,
    Url,
    FileHash,
    Email,
    FilePath,
    Registry,
    Mutex,
    UserAgent,
    Certificate,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "threat_actor_type", rename_all = "lowercase")]
pub enum ThreatActorType {
    NationState,
    Cybercrime,
    Hacktivist,
    Insider,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatIndicator {
    pub id: Uuid,
    pub tenant_id: String,
    pub indicator_type: IndicatorType,
    pub value: String,
    pub confidence: f64,
    pub severity: String,
    pub description: Option<String>,
    pub source: String,
    pub external_source_id: Option<String>,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub expiry: Option<DateTime<Utc>>,
    pub is_active: bool,
    pub related_threat_ids: Vec<String>,
    pub related_actor_ids: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatActor {
    pub id: Uuid,
    pub tenant_id: String,
    pub name: String,
    pub actor_type: ThreatActorType,
    pub description: Option<String>,
    pub aliases: Vec<String>,
    pub motivations: Vec<String>,
    pub techniques: Vec<String>,
    pub targets: Vec<String>,
    pub confidence: f64,
    pub source: String,
    pub first_seen: Option<DateTime<Utc>>,
    pub last_seen: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatCampaign {
    pub id: Uuid,
    pub tenant_id: String,
    pub name: String,
    pub description: Option<String>,
    pub actor_id: Option<String>,
    pub techniques: Vec<String>,
    pub indicators: Vec<String>,
    pub targets: Vec<String>,
    pub confidence: f64,
    pub source: String,
    pub first_seen: Option<DateTime<Utc>>,
    pub last_seen: Option<DateTime<Utc>>,
    pub is_active: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateIndicatorRequest {
    pub tenant_id: String,
    pub indicator_type: IndicatorType,
    pub value: String,
    pub confidence: f64,
    pub severity: String,
    pub description: Option<String>,
    pub source: String,
    pub expiry: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndicatorResponse {
    pub id: String,
    pub tenant_id: String,
    pub indicator_type: String,
    pub value: String,
    pub confidence: f64,
    pub severity: String,
    pub source: String,
    pub is_active: bool,
    pub first_seen: String,
    pub last_seen: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntelligenceStats {
    pub total_indicators: i64,
    pub active_indicators: i64,
    pub total_actors: i64,
    pub total_campaigns: i64,
    pub by_type: Vec<(String, i64)>,
    pub by_severity: Vec<(String, i64)>,
}
