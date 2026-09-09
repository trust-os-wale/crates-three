use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "evidence_type", rename_all = "lowercase")]
pub enum SecurityEvidenceType {
    Log,
    Screenshot,
    NetworkCapture,
    MemoryDump,
    DiskImage,
    MalwareSample,
    Configuration,
    Policy,
    AuditRecord,
    Timeline,
    Interview,
    Other,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "evidence_status", rename_all = "lowercase")]
pub enum EvidenceStatus {
    Collected,
    Verified,
    Analyzed,
    Archived,
    Disputed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityEvidence {
    pub id: Uuid,
    pub tenant_id: String,
    pub evidence_type: SecurityEvidenceType,
    pub status: EvidenceStatus,
    pub title: String,
    pub description: String,
    pub collection_method: String,
    pub collected_by: String,
    pub collected_at: DateTime<Utc>,
    pub content_hash: String,
    pub content_size: i64,
    pub content_type: String,
    pub storage_path: String,
    pub storage_bucket: Option<String>,
    pub storage_region: Option<String>,
    pub encryption_key_id: Option<String>,
    pub integrity_verified: bool,
    pub integrity_verified_at: Option<DateTime<Utc>>,
    pub chain_of_custody: Vec<CustodyEntry>,
    pub related_threat_ids: Vec<String>,
    pub related_incident_ids: Vec<String>,
    pub related_vulnerability_ids: Vec<String>,
    pub related_asset_ids: Vec<String>,
    pub metadata: Option<serde_json::Value>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustodyEntry {
    pub timestamp: DateTime<Utc>,
    pub action: String,
    pub actor_id: String,
    pub actor_type: String,
    pub details: Option<String>,
    pub hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateEvidenceRequest {
    pub tenant_id: String,
    pub evidence_type: SecurityEvidenceType,
    pub title: String,
    pub description: String,
    pub collection_method: String,
    pub collected_by: String,
    pub content_type: String,
    pub related_threat_ids: Vec<String>,
    pub related_incident_ids: Vec<String>,
    pub related_vulnerability_ids: Vec<String>,
    pub related_asset_ids: Vec<String>,
    pub metadata: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceResponse {
    pub id: String,
    pub tenant_id: String,
    pub evidence_type: String,
    pub status: String,
    pub title: String,
    pub description: String,
    pub collected_by: String,
    pub collected_at: String,
    pub content_hash: String,
    pub content_size: i64,
    pub integrity_verified: bool,
    pub chain_of_custody_count: i64,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceStats {
    pub total: i64,
    pub by_type: Vec<(String, i64)>,
    pub by_status: Vec<(String, i64)>,
    pub verified: i64,
    pub total_size_bytes: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyEvidenceRequest {
    pub verified_by: String,
    pub notes: Option<String>,
}
