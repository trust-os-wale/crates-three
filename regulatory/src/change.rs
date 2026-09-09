//! Regulatory change detection and impact analysis.
//!
//! Detects and analyzes regulation/framework changes (new, amended, repealed,
//! superseded) and computes per-requirement/control impacts so the platform
//! can react with governed actions.

use crate::{Priority, RegulationRequirement};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ChangeType {
    NewRegulation,
    Amendment,
    Repeal,
    Supersession,
    InterpretationUpdate,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ChangeStatus {
    Detected,
    Analyzed,
    Assessed,
    Applied,
    Rejected,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ChangeImpactLevel {
    High,
    Medium,
    Low,
    Unknown,
}

impl ChangeImpactLevel {
    pub fn priority(&self) -> Priority {
        match self {
            Self::High => Priority::High,
            Self::Medium => Priority::Medium,
            Self::Low => Priority::Low,
            Self::Unknown => Priority::Medium,
        }
    }
}

/// A detected change to a regulation (or framework).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegulatoryChange {
    pub id: String,
    pub tenant_id: String,
    pub regulation_id: String,
    pub change_type: ChangeType,
    pub title: String,
    pub description: String,
    pub change_number: String,
    pub effective_date: Option<chrono::DateTime<chrono::Utc>>,
    pub status: ChangeStatus,
    pub detected_at: chrono::DateTime<chrono::Utc>,
    pub source_id: Option<String>,
    pub source_reference: Option<String>,
}

/// Impact of a change on one requirement or control.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChangeImpact {
    pub id: String,
    pub tenant_id: String,
    pub change_id: String,
    pub requirement_id: Option<String>,
    pub control_id: Option<String>,
    pub impact_level: ChangeImpactLevel,
    pub description: String,
    pub recommended_actions: Vec<String>,
    pub confidence: f64,
    pub assessed_at: chrono::DateTime<chrono::Utc>,
}

/// Pure change analysis over requirement diffs.
pub struct ChangeEngine;

impl ChangeEngine {
    /// Diff two requirement sets of a regulation version pair and produce
    /// impacts for requirements that were added, removed, or materially
    /// modified. Modified mandatory requirements rank higher.
    pub fn analyze_requirements_diff(
        change: &RegulatoryChange,
        previous: &[RegulationRequirement],
        current: &[RegulationRequirement],
    ) -> Vec<ChangeImpact> {
        let previous_by_code: HashMap<&str, &RegulationRequirement> = previous
            .iter()
            .map(|r| (r.requirement_code.as_str(), r))
            .collect();
        let current_by_code: HashMap<&str, &RegulationRequirement> = current
            .iter()
            .map(|r| (r.requirement_code.as_str(), r))
            .collect();

        let mut impacts = Vec::new();

        for (code, req) in &current_by_code {
            match previous_by_code.get(code) {
                None => {
                    let level = if req.is_mandatory {
                        ChangeImpactLevel::High
                    } else {
                        ChangeImpactLevel::Medium
                    };
                    impacts.push(Self::impact(
                        change,
                        Some(req.id.clone()),
                        None,
                        level,
                        format!(
                            "New requirement '{}' ({}) introduced by {}",
                            req.requirement_code, req.title, change.change_number
                        ),
                        vec!["Review requirement and map to canonical controls".to_string()],
                        1.0,
                    ));
                }
                Some(prev) => {
                    let modified = prev.title != req.title
                        || prev.description != req.description
                        || prev.is_mandatory != req.is_mandatory
                        || prev.requirement_type != req.requirement_type;
                    if modified {
                        let level = if req.is_mandatory {
                            ChangeImpactLevel::High
                        } else {
                            ChangeImpactLevel::Medium
                        };
                        impacts.push(Self::impact(
                            change,
                            Some(req.id.clone()),
                            None,
                            level,
                            format!(
                                "Requirement '{}' was modified by {}",
                                req.requirement_code, change.change_number
                            ),
                            vec![
                                "Re-assess requirement satisfaction".to_string(),
                                "Re-verify mapped controls".to_string(),
                            ],
                            0.9,
                        ));
                    }
                }
            }
        }

        for (code, prev) in &previous_by_code {
            if !current_by_code.contains_key(code) {
                impacts.push(Self::impact(
                    change,
                    Some(prev.id.clone()),
                    None,
                    ChangeImpactLevel::Low,
                    format!(
                        "Requirement '{}' was removed by {}",
                        prev.requirement_code, change.change_number
                    ),
                    vec!["Confirm no obligations remain from removed requirement".to_string()],
                    0.9,
                ));
            }
        }

        impacts.sort_by_key(|i| i.impact_level.priority().rank());
        impacts
    }

    fn impact(
        change: &RegulatoryChange,
        requirement_id: Option<String>,
        control_id: Option<String>,
        impact_level: ChangeImpactLevel,
        description: String,
        recommended_actions: Vec<String>,
        confidence: f64,
    ) -> ChangeImpact {
        ChangeImpact {
            id: uuid::Uuid::new_v4().to_string(),
            tenant_id: change.tenant_id.clone(),
            change_id: change.id.clone(),
            requirement_id,
            control_id,
            impact_level,
            description,
            recommended_actions,
            confidence,
            assessed_at: chrono::Utc::now(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(code: &str, title: &str, mandatory: bool) -> RegulationRequirement {
        RegulationRequirement {
            id: format!("req-{code}"),
            regulation_id: "reg-1".to_string(),
            regulation_version_id: "v1".to_string(),
            requirement_code: code.to_string(),
            title: title.to_string(),
            description: "description".to_string(),
            requirement_type: crate::RequirementType::GeneralObligation,
            is_mandatory: mandatory,
            enforcement_level: None,
            source_article: None,
            ai_extracted: false,
            ai_model_id: None,
            ai_confidence: None,
            requires_human_review: false,
            review_status: crate::RequirementReviewStatus::Approved,
            review_notes: None,
            effective_from: None,
            effective_to: None,
            supersedes_id: None,
        }
    }

    fn change() -> RegulatoryChange {
        RegulatoryChange {
            id: "chg-1".to_string(),
            tenant_id: "tenant-1".to_string(),
            regulation_id: "reg-1".to_string(),
            change_type: ChangeType::Amendment,
            title: "Test amendment".to_string(),
            description: "".to_string(),
            change_number: "2026/001".to_string(),
            effective_date: None,
            status: ChangeStatus::Detected,
            detected_at: chrono::Utc::now(),
            source_id: None,
            source_reference: None,
        }
    }

    #[test]
    fn test_new_mandatory_requirement_is_high_impact() {
        let previous = vec![req("a1", "Article 1", true)];
        let current = vec![req("a1", "Article 1", true), req("a2", "Article 2", true)];
        let impacts = ChangeEngine::analyze_requirements_diff(&change(), &previous, &current);
        assert_eq!(impacts.len(), 1);
        assert_eq!(impacts[0].impact_level, ChangeImpactLevel::High);
        assert_eq!(impacts[0].requirement_id.as_deref(), Some("req-a2"));
    }

    #[test]
    fn test_modified_requirement_detected() {
        let previous = vec![req("a1", "Article 1", true)];
        let current = vec![req("a1", "Article 1 (amended)", true)];
        let impacts = ChangeEngine::analyze_requirements_diff(&change(), &previous, &current);
        assert_eq!(impacts.len(), 1);
        assert_eq!(impacts[0].impact_level, ChangeImpactLevel::High);
    }

    #[test]
    fn test_removed_requirement_is_low_impact() {
        let previous = vec![req("a1", "Article 1", true), req("a2", "Article 2", false)];
        let current = vec![req("a1", "Article 1", true)];
        let impacts = ChangeEngine::analyze_requirements_diff(&change(), &previous, &current);
        assert_eq!(impacts.len(), 1);
        assert_eq!(impacts[0].impact_level, ChangeImpactLevel::Low);
    }

    #[test]
    fn test_no_changes_no_impacts() {
        let previous = vec![req("a1", "Article 1", true)];
        let current = vec![req("a1", "Article 1", true)];
        let impacts = ChangeEngine::analyze_requirements_diff(&change(), &previous, &current);
        assert!(impacts.is_empty());
    }
}
