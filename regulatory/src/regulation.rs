//! Regulation domain types with versioning.
//!
//! A regulation has a lineage of versions (`regulations` +
//! `regulation_versions` in migration 005). Requirements belong to a specific
//! regulation version. Version history is immutable: superseded versions are
//! never modified or deleted.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RegulationStatus {
    Draft,
    InForce,
    PartiallyInForce,
    Amended,
    Superseded,
    Repealed,
}

/// A regulation (e.g. GDPR). The current version is tracked on the
/// regulation row; all historical versions remain available.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Regulation {
    pub id: String,
    pub title: String,
    pub short_title: String,
    pub regulation_number: String,
    pub authority_id: String,
    pub jurisdiction_id: String,
    pub current_version_id: Option<String>,
    pub status: RegulationStatus,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// A single version of a regulation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegulationVersion {
    pub id: String,
    pub regulation_id: String,
    pub version_number: i64,
    pub version_label: String,
    pub effective_from: Option<chrono::DateTime<chrono::Utc>>,
    pub effective_to: Option<chrono::DateTime<chrono::Utc>>,
    pub status: RegulationStatus,
    pub changelog: Option<String>,
    pub source_id: Option<String>,
    pub supersedes_id: Option<String>,
    pub superseded_by: Option<String>,
    pub published_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RequirementType {
    GeneralObligation,
    Prohibition,
    Permission,
    Reporting,
    Notification,
    RecordKeeping,
    TechnicalStandard,
    ProcessStandard,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RequirementReviewStatus {
    Pending,
    Approved,
    Rejected,
    NeedsClarification,
}

/// A requirement belonging to one regulation version.
///
/// AI-extracted requirements are flagged (`ai_extracted`, `ai_confidence`,
/// `requires_human_review`) and are never treated as authoritative until
/// reviewed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegulationRequirement {
    pub id: String,
    pub regulation_id: String,
    pub regulation_version_id: String,
    pub requirement_code: String,
    pub title: String,
    pub description: String,
    pub requirement_type: RequirementType,
    pub is_mandatory: bool,
    pub enforcement_level: Option<String>,
    pub source_article: Option<String>,
    pub ai_extracted: bool,
    pub ai_model_id: Option<String>,
    pub ai_confidence: Option<f64>,
    pub requires_human_review: bool,
    pub review_status: RequirementReviewStatus,
    pub review_notes: Option<String>,
    pub effective_from: Option<chrono::DateTime<chrono::Utc>>,
    pub effective_to: Option<chrono::DateTime<chrono::Utc>>,
    pub supersedes_id: Option<String>,
}

/// A recurring obligation derived from a requirement
/// (e.g. annual risk assessment, 72h breach notification).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegulatoryObligation {
    pub id: String,
    pub requirement_id: String,
    pub obligation_type: String,
    pub description: String,
    pub frequency: Option<String>,
    pub deadline_days: Option<i32>,
    pub applies_to: Option<String>,
}

/// A deadline bound to a trigger event of an obligation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegulatoryDeadline {
    pub id: String,
    pub obligation_id: String,
    pub deadline_type: String,
    pub trigger_event: Option<String>,
    pub due_offset_days: i32,
    pub notes: Option<String>,
}

/// Pure versioning logic for regulations.
pub struct RegulationVersionEngine;

impl RegulationVersionEngine {
    /// The version currently in force for the given point in time.
    pub fn current_version<'a>(
        versions: &'a [RegulationVersion],
        now: chrono::DateTime<chrono::Utc>,
    ) -> Option<&'a RegulationVersion> {
        Self::version_at(versions, now)
    }

    /// The version in force at a specific point in time
    /// (highest version number within the effective window).
    pub fn version_at<'a>(
        versions: &'a [RegulationVersion],
        at: chrono::DateTime<chrono::Utc>,
    ) -> Option<&'a RegulationVersion> {
        versions
            .iter()
            .filter(|v| v.status == RegulationStatus::InForce)
            .filter(|v| v.effective_from.map(|f| f <= at).unwrap_or(true))
            .filter(|v| v.effective_to.map(|t| at <= t).unwrap_or(true))
            .max_by_key(|v| v.version_number)
    }

    /// Link version `new_id` as the superseding version of `old_id`.
    ///
    /// Never overwrites history: the old version is marked SUPERSEDED and its
    /// `superseded_by` is set; the new version records `supersedes_id`.
    pub fn supersede(
        versions: &mut [RegulationVersion],
        old_id: &str,
        new_id: &str,
    ) -> Result<(), String> {
        if old_id == new_id {
            return Err("A version cannot supersede itself".to_string());
        }
        let old = versions
            .iter_mut()
            .find(|v| v.id == old_id)
            .ok_or_else(|| format!("Version '{}' not found", old_id))?;
        old.superseded_by = Some(new_id.to_string());
        old.status = RegulationStatus::Superseded;
        let new = versions
            .iter_mut()
            .find(|v| v.id == new_id)
            .ok_or_else(|| format!("Version '{}' not found", new_id))?;
        new.supersedes_id = Some(old_id.to_string());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn version(
        id: &str,
        number: i64,
        effective_from: &str,
        status: RegulationStatus,
    ) -> RegulationVersion {
        RegulationVersion {
            id: id.to_string(),
            regulation_id: "reg-1".to_string(),
            version_number: number,
            version_label: id.to_string(),
            effective_from: Some(
                chrono::DateTime::parse_from_rfc3339(effective_from)
                    .unwrap()
                    .with_timezone(&chrono::Utc),
            ),
            effective_to: None,
            status,
            changelog: None,
            source_id: None,
            supersedes_id: None,
            superseded_by: None,
            published_at: None,
        }
    }

    fn at(rfc3339: &str) -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::parse_from_rfc3339(rfc3339)
            .unwrap()
            .with_timezone(&chrono::Utc)
    }

    #[test]
    fn test_version_at_picks_highest_in_force() {
        let versions = vec![
            version("v1", 1, "2020-01-01T00:00:00Z", RegulationStatus::InForce),
            version("v2", 2, "2023-01-01T00:00:00Z", RegulationStatus::InForce),
        ];
        let current =
            RegulationVersionEngine::current_version(&versions, at("2024-01-01T00:00:00Z"));
        assert_eq!(current.unwrap().id, "v2");
    }

    #[test]
    fn test_version_at_ignores_future_versions() {
        let versions = vec![version(
            "v1",
            1,
            "2020-01-01T00:00:00Z",
            RegulationStatus::InForce,
        )];
        let current =
            RegulationVersionEngine::current_version(&versions, at("2021-01-01T00:00:00Z"));
        assert_eq!(current.unwrap().id, "v1");
    }

    #[test]
    fn test_supersede_links_history() {
        let mut versions = vec![
            version("v1", 1, "2020-01-01T00:00:00Z", RegulationStatus::InForce),
            version("v2", 2, "2023-01-01T00:00:00Z", RegulationStatus::InForce),
        ];
        RegulationVersionEngine::supersede(&mut versions, "v1", "v2").unwrap();
        assert_eq!(versions[0].status, RegulationStatus::Superseded);
        assert_eq!(versions[0].superseded_by.as_deref(), Some("v2"));
        assert_eq!(versions[1].supersedes_id.as_deref(), Some("v1"));
    }
}
