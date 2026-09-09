//! Framework domain types with versioning.
//!
//! Frameworks (SOC 2, ISO 27001, PCI DSS, HIPAA, ...) are versioned the same
//! way regulations are: `frameworks` + `framework_versions` +
//! `framework_requirements` in migration 005.

use crate::ControlType;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FrameworkStatus {
    Draft,
    Published,
    Retired,
}

/// A compliance framework. The current version is tracked on the row;
/// all historical versions remain available.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Framework {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub status: FrameworkStatus,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// A single version of a framework.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FrameworkVersion {
    pub id: String,
    pub framework_id: String,
    pub version_number: i64,
    pub version_label: String,
    pub effective_from: Option<chrono::DateTime<chrono::Utc>>,
    pub effective_to: Option<chrono::DateTime<chrono::Utc>>,
    pub status: FrameworkStatus,
    pub changelog: Option<String>,
    pub source_id: Option<String>,
}

/// A requirement/control defined by one framework version.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FrameworkRequirement {
    pub id: String,
    pub framework_id: String,
    pub framework_version_id: String,
    pub requirement_code: String,
    pub title: String,
    pub description: String,
    pub category: Option<String>,
    pub control_type: Option<ControlType>,
    pub is_mandatory: bool,
    pub effective_from: Option<chrono::DateTime<chrono::Utc>>,
    pub effective_to: Option<chrono::DateTime<chrono::Utc>>,
    pub supersedes_id: Option<String>,
}

/// Pure versioning logic for frameworks.
pub struct FrameworkVersionEngine;

impl FrameworkVersionEngine {
    /// The version currently in force.
    pub fn current_version<'a>(
        versions: &'a [FrameworkVersion],
        now: chrono::DateTime<chrono::Utc>,
    ) -> Option<&'a FrameworkVersion> {
        versions
            .iter()
            .filter(|v| v.status == FrameworkStatus::Published)
            .filter(|v| v.effective_from.map(|f| f <= now).unwrap_or(true))
            .filter(|v| v.effective_to.map(|t| now <= t).unwrap_or(true))
            .max_by_key(|v| v.version_number)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn version(id: &str, number: i64) -> FrameworkVersion {
        FrameworkVersion {
            id: id.to_string(),
            framework_id: "fw-1".to_string(),
            version_number: number,
            version_label: id.to_string(),
            effective_from: None,
            effective_to: None,
            status: FrameworkStatus::Published,
            changelog: None,
            source_id: None,
        }
    }

    #[test]
    fn test_current_version_is_highest() {
        let versions = vec![version("v1", 1), version("v2", 2)];
        let current = FrameworkVersionEngine::current_version(&versions, chrono::Utc::now());
        assert_eq!(current.unwrap().id, "v2");
    }

    #[test]
    fn test_retired_versions_are_not_current() {
        let mut v1 = version("v1", 2);
        v1.status = FrameworkStatus::Retired;
        let versions = vec![v1, version("v0", 1)];
        let current = FrameworkVersionEngine::current_version(&versions, chrono::Utc::now());
        assert_eq!(current.unwrap().id, "v0");
    }
}
