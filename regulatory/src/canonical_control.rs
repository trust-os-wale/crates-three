//! Canonical control domain types.
//!
//! A canonical control is the platform-neutral control (e.g. "encryption at
//! rest") that requirements from many regulations and frameworks map to.
//! Customer control implementations instantiate a canonical control inside
//! one tenant.

use crate::RecordStatus;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ControlType {
    Technical,
    Organizational,
    Physical,
}

/// Platform-neutral canonical control.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CanonicalControl {
    pub id: String,
    pub code: String,
    pub name: String,
    pub description: String,
    pub control_type: ControlType,
    pub category: Option<String>,
    pub version: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// Tenant-specific implementation of a canonical control.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlImplementation {
    pub id: String,
    pub tenant_id: String,
    pub control_id: String,
    pub implementation_type: String,
    pub status: RecordStatus,
    pub description: Option<String>,
    pub configuration: serde_json::Value,
    pub owner: Option<String>,
    pub verified_at: Option<chrono::DateTime<chrono::Utc>>,
    pub valid_until: Option<chrono::DateTime<chrono::Utc>>,
}

impl ControlImplementation {
    /// True when the implementation is active and its verification is fresh.
    pub fn is_current(&self, now: chrono::DateTime<chrono::Utc>) -> bool {
        self.status == RecordStatus::Active && self.valid_until.map(|v| now <= v).unwrap_or(true)
    }
}
