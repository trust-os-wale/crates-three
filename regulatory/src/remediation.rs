//! Governed remediation domain types.

use crate::Priority;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RemediationStatus {
    Open,
    InProgress,
    Completed,
    Verified,
    Rejected,
    Cancelled,
}

/// A governed remediation action bound to a finding/requirement.
///
/// High-impact remediations require approval before execution; completion is
/// verified against fresh evidence (`evidence_after_id`,
/// `verification_result`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemediationAction {
    pub id: String,
    pub tenant_id: String,
    pub finding_id: Option<String>,
    pub requirement_id: Option<String>,
    pub control_id: Option<String>,
    pub title: String,
    pub description: Option<String>,
    pub approval_required: bool,
    pub approval_status: Option<String>,
    pub workflow_id: Option<String>,
    pub due_date: Option<chrono::DateTime<chrono::Utc>>,
    pub assigned_to: Option<String>,
    pub priority: Priority,
    pub status: RemediationStatus,
    pub verification_method: Option<String>,
    pub evidence_before_id: Option<String>,
    pub evidence_after_id: Option<String>,
    pub verification_result: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

impl RemediationAction {
    /// True when the action is still open/in-progress and past its due date.
    pub fn is_overdue(&self, now: chrono::DateTime<chrono::Utc>) -> bool {
        matches!(
            self.status,
            RemediationStatus::Open | RemediationStatus::InProgress
        ) && self.due_date.map(|d| now > d).unwrap_or(false)
    }

    /// True when approval is required and has not been granted.
    pub fn requires_approval(&self) -> bool {
        self.approval_required && self.approval_status.as_deref() != Some("approved")
    }

    /// True when the remediation is verified complete.
    pub fn is_verified(&self) -> bool {
        self.status == RemediationStatus::Verified
    }
}
