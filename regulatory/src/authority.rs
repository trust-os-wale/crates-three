//! Regulatory authority and source registry domain types.
//!
//! The source registry tracks provenance (source hash, content hash,
//! publication metadata) for every regulation and framework ingested into
//! Trust OS. Production content must be ingested from official sources; the
//! database is authoritative, never hard-coded data.

use crate::RecordStatus;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AuthorityType {
    Regulator,
    Supervisor,
    StandardsBody,
    SelfRegulatory,
}

/// A regulatory authority, supervisor, or standards body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegulatoryAuthority {
    pub id: String,
    pub name: String,
    pub short_name: Option<String>,
    pub jurisdiction_id: Option<String>,
    pub authority_type: AuthorityType,
    pub website: Option<String>,
    pub description: Option<String>,
    pub status: RecordStatus,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SourceType {
    OfficialGazette,
    Statute,
    RegulationText,
    Guidance,
    Standard,
    Decision,
    Amendment,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SourceStatus {
    Draft,
    Published,
    Archived,
    Revoked,
}

/// A source document in the regulatory source registry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegulatorySource {
    pub id: String,
    pub authority_id: Option<String>,
    pub source_type: SourceType,
    pub title: String,
    pub reference_number: Option<String>,
    pub url: Option<String>,
    pub published_at: Option<chrono::DateTime<chrono::Utc>>,
    pub source_hash: Option<String>,
    pub content_hash: Option<String>,
    pub provenance: Option<String>,
    pub status: SourceStatus,
}
