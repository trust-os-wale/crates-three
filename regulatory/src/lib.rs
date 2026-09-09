//! Regulatory intelligence domain library for Trust OS.
//!
//! Normalized multi-jurisdiction regulatory domain model:
//! Organization -> Jurisdiction -> Industry -> Business Activity ->
//! Applicability -> Regulation/Framework (versioned) -> Requirement ->
//! Canonical Control -> Mapping -> Evidence -> Continuous Assessment ->
//! Finding/Exception -> Remediation.
//!
//! The PostgreSQL database (see `data/migrations/005_regulatory_intelligence`)
//! is the authoritative source of regulatory content. This crate provides the
//! domain types and the deterministic logic engines (applicability,
//! versioning, change analysis, assessment aggregation, mapping resolution)
//! used by the `regulatory-intelligence` and `compliance-as-code` services.

pub mod applicability;
pub mod assessment;
pub mod authority;
pub mod business_activity;
pub mod canonical_control;
pub mod change;
pub mod framework;
pub mod industry;
pub mod jurisdiction;
pub mod mapping;
pub mod organization;
pub mod regulation;
pub mod remediation;

pub mod frameworks;
pub mod rules;
pub mod tracking;

pub use applicability::*;
pub use assessment::*;
pub use authority::*;
pub use business_activity::*;
pub use canonical_control::*;
pub use change::*;
pub use framework::*;
pub use industry::*;
pub use jurisdiction::*;
pub use mapping::*;
pub use organization::*;
pub use regulation::*;
pub use remediation::*;

use serde::{Deserialize, Serialize};

/// Regulatory framework identifier
pub type FrameworkId = String;

/// Compliance status used for requirements, assessments and posture.
///
/// Mirrors the `assessment_status` enum in migration 005. Serde names are
/// lowercase snake_case to match the PostgreSQL enum values.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ComplianceStatus {
    Compliant,
    PartiallyCompliant,
    NonCompliant,
    NotAssessed,
    NotApplicable,
    RequiresReview,
    EvidenceExpired,
}

impl ComplianceStatus {
    /// Statuses that do not indicate a compliance gap.
    pub fn is_passive(&self) -> bool {
        matches!(self, Self::NotApplicable | Self::NotAssessed)
    }
}

/// Priority used for findings, remediation and change impacts.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Priority {
    Critical,
    High,
    Medium,
    Low,
}

impl Priority {
    pub fn rank(&self) -> u8 {
        match self {
            Self::Critical => 0,
            Self::High => 1,
            Self::Medium => 2,
            Self::Low => 3,
        }
    }
}

/// Generic lifecycle status for reference records (organizations,
/// jurisdictions, industries, activities, authorities, controls).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RecordStatus {
    Active,
    Inactive,
    Draft,
    Archived,
}
