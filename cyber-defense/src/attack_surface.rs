use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "asset_type", rename_all = "lowercase")]
pub enum AssetType {
    Application,
    Api,
    Endpoint,
    Domain,
    CloudResource,
    Network,
    Database,
    Identity,
    Container,
    Server,
    Service,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "asset_exposure", rename_all = "lowercase")]
pub enum AssetExposure {
    InternetFacing,
    VpnOnly,
    Internal,
    AirGapped,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "asset_criticality", rename_all = "lowercase")]
pub enum AssetCriticality {
    Critical,
    High,
    Medium,
    Low,
    None,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackSurfaceAsset {
    pub id: Uuid,
    pub tenant_id: String,
    pub name: String,
    pub asset_type: AssetType,
    pub exposure: AssetExposure,
    pub criticality: AssetCriticality,
    pub owner_id: Option<String>,
    pub environment: Option<String>,
    pub ip_addresses: Vec<String>,
    pub domains: Vec<String>,
    pub ports: Vec<i32>,
    pub technologies: Vec<String>,
    pub cloud_provider: Option<String>,
    pub cloud_region: Option<String>,
    pub cloud_account_id: Option<String>,
    pub compliance_scope: Vec<String>,
    pub trust_score: Option<f64>,
    pub risk_score: Option<f64>,
    pub vulnerability_count: i64,
    pub last_scan_at: Option<DateTime<Utc>>,
    pub discovered_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateAssetRequest {
    pub tenant_id: String,
    pub name: String,
    pub asset_type: AssetType,
    pub exposure: AssetExposure,
    pub criticality: AssetCriticality,
    pub owner_id: Option<String>,
    pub environment: Option<String>,
    pub ip_addresses: Vec<String>,
    pub domains: Vec<String>,
    pub ports: Vec<i32>,
    pub technologies: Vec<String>,
    pub cloud_provider: Option<String>,
    pub cloud_region: Option<String>,
    pub cloud_account_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssetResponse {
    pub id: String,
    pub tenant_id: String,
    pub name: String,
    pub asset_type: String,
    pub exposure: String,
    pub criticality: String,
    pub owner_id: Option<String>,
    pub environment: Option<String>,
    pub trust_score: Option<f64>,
    pub risk_score: Option<f64>,
    pub vulnerability_count: i64,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssetStats {
    pub total: i64,
    pub internet_facing: i64,
    pub critical: i64,
    pub high: i64,
    pub with_vulnerabilities: i64,
    pub by_type: Vec<(String, i64)>,
    pub by_exposure: Vec<(String, i64)>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackPath {
    pub path_id: String,
    pub nodes: Vec<AttackPathNode>,
    pub edges: Vec<AttackPathEdge>,
    pub risk_score: f64,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackPathNode {
    pub node_id: String,
    pub node_type: String,
    pub label: String,
    pub risk_score: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackPathEdge {
    pub source: String,
    pub target: String,
    pub relationship: String,
    pub weight: f64,
}
