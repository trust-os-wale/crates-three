//! Organization and organizational-attachment domain types.

use crate::RecordStatus;
use serde::{Deserialize, Serialize};

/// An organization (tenant) subject to regulations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Organization {
    pub id: String,
    pub name: String,
    pub legal_name: Option<String>,
    pub jurisdiction_id: Option<String>,
    pub status: RecordStatus,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

/// Attachment of an organization to a jurisdiction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrganizationJurisdiction {
    pub id: String,
    pub organization_id: String,
    pub jurisdiction_id: String,
    pub status: RecordStatus,
    pub effective_from: Option<chrono::DateTime<chrono::Utc>>,
    pub effective_to: Option<chrono::DateTime<chrono::Utc>>,
    pub notes: Option<String>,
}

impl OrganizationJurisdiction {
    pub fn is_current(&self, now: chrono::DateTime<chrono::Utc>) -> bool {
        self.status == RecordStatus::Active
            && self.effective_from.map(|f| f <= now).unwrap_or(true)
            && self.effective_to.map(|t| now <= t).unwrap_or(true)
    }
}

/// Attachment of an organization to an industry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrganizationIndustry {
    pub id: String,
    pub organization_id: String,
    pub industry_id: String,
    pub is_primary: bool,
}

/// Attachment of an organization to a business activity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrganizationBusinessActivity {
    pub id: String,
    pub organization_id: String,
    pub activity_id: String,
    pub status: RecordStatus,
}

/// A license or registration held by an organization.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct License {
    pub id: String,
    pub organization_id: String,
    pub authority_id: String,
    pub license_type: String,
    pub number: String,
    pub jurisdiction_id: Option<String>,
    pub status: RecordStatus,
    pub issued_at: Option<chrono::DateTime<chrono::Utc>>,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
}

impl License {
    pub fn is_valid(&self, now: chrono::DateTime<chrono::Utc>) -> bool {
        self.status == RecordStatus::Active && self.expires_at.map(|e| now <= e).unwrap_or(true)
    }
}
