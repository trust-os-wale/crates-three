//! Mapping domain types and resolution.
//!
//! Maps connect requirements to canonical controls (`control_mappings`),
//! requirements to specific controls (`requirement_mappings`), risks to
//! controls (`risk_mappings`) and define what evidence satisfies a control
//! (`evidence_requirements`). AI-suggested mappings are never verified by
//! default.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MappingType {
    RegulationToControl,
    ControlToRequirement,
    RequirementToControl,
    FrameworkToControl,
    RiskToControl,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MappingVerificationStatus {
    Verified,
    Unverified,
    RequiresReview,
    AiSuggested,
}

/// Mapping between two regulatory artifacts (e.g. requirement <-> control).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlMapping {
    pub id: String,
    pub tenant_id: String,
    pub mapping_type: MappingType,
    pub source_id: String,
    pub target_id: String,
    pub confidence: f64,
    pub justification: String,
    pub verification_status: MappingVerificationStatus,
    pub ai_generated: bool,
    pub ai_model_id: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

/// Requirement -> control mapping (used for assessment resolution).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequirementMapping {
    pub id: String,
    pub tenant_id: String,
    pub requirement_id: String,
    pub control_id: String,
    pub mapping_type: MappingType,
    pub rationale: Option<String>,
    pub confidence: f64,
    pub verification_status: MappingVerificationStatus,
}

/// Risk -> control mapping.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskMapping {
    pub id: String,
    pub tenant_id: String,
    pub risk_id: String,
    pub control_id: String,
    pub mapping_type: MappingType,
    pub effectiveness: Option<f64>,
}

/// What evidence a requirement/control requires.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceRequirement {
    pub id: String,
    pub tenant_id: String,
    pub requirement_id: Option<String>,
    pub control_id: Option<String>,
    pub evidence_type: String,
    pub frequency: Option<String>,
    pub retention_days: Option<i32>,
    pub description: Option<String>,
}

/// Pure mapping resolution. Only verified mappings are considered
/// authoritative; AI-suggested or unverified mappings are excluded unless
/// explicitly requested.
pub struct MappingEngine;

impl MappingEngine {
    /// Controls mapped to a requirement (verified only).
    pub fn controls_for_requirement<'a>(
        requirement_id: &str,
        tenant_id: &str,
        mappings: &'a [RequirementMapping],
    ) -> Vec<&'a str> {
        mappings
            .iter()
            .filter(|m| {
                m.tenant_id == tenant_id
                    && m.requirement_id == requirement_id
                    && m.verification_status == MappingVerificationStatus::Verified
            })
            .map(|m| m.control_id.as_str())
            .collect()
    }

    /// Requirements mapped to a control (verified only).
    pub fn requirements_for_control<'a>(
        control_id: &str,
        tenant_id: &str,
        mappings: &'a [RequirementMapping],
    ) -> Vec<&'a str> {
        mappings
            .iter()
            .filter(|m| {
                m.tenant_id == tenant_id
                    && m.control_id == control_id
                    && m.verification_status == MappingVerificationStatus::Verified
            })
            .map(|m| m.requirement_id.as_str())
            .collect()
    }

    /// Coverage of a requirement: verified controls as a fraction of all
    /// controls ever mapped to it (including unverified/AI-suggested).
    pub fn requirement_coverage(
        requirement_id: &str,
        tenant_id: &str,
        mappings: &[RequirementMapping],
    ) -> f64 {
        let all: Vec<&RequirementMapping> = mappings
            .iter()
            .filter(|m| m.tenant_id == tenant_id && m.requirement_id == requirement_id)
            .collect();
        if all.is_empty() {
            return 0.0;
        }
        let verified = all
            .iter()
            .filter(|m| m.verification_status == MappingVerificationStatus::Verified)
            .count();
        verified as f64 / all.len() as f64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mapping(requirement_id: &str, control_id: &str, verified: bool) -> RequirementMapping {
        RequirementMapping {
            id: uuid::Uuid::new_v4().to_string(),
            tenant_id: "tenant-1".to_string(),
            requirement_id: requirement_id.to_string(),
            control_id: control_id.to_string(),
            mapping_type: MappingType::RequirementToControl,
            rationale: None,
            confidence: 1.0,
            verification_status: if verified {
                MappingVerificationStatus::Verified
            } else {
                MappingVerificationStatus::AiSuggested
            },
        }
    }

    #[test]
    fn test_controls_for_requirement_only_verified() {
        let mappings = vec![
            mapping("req-1", "c-1", true),
            mapping("req-1", "c-2", true),
            mapping("req-1", "c-3", false),
            mapping("req-2", "c-9", true),
        ];
        let controls = MappingEngine::controls_for_requirement("req-1", "tenant-1", &mappings);
        assert_eq!(controls.len(), 2);
        assert!(controls.contains(&"c-1"));
        assert!(!controls.contains(&"c-3"));
    }

    #[test]
    fn test_requirements_for_control() {
        let mappings = vec![mapping("req-1", "c-1", true), mapping("req-2", "c-1", true)];
        let requirements = MappingEngine::requirements_for_control("c-1", "tenant-1", &mappings);
        assert_eq!(requirements.len(), 2);
    }

    #[test]
    fn test_coverage_counts_ai_suggestions() {
        let mappings = vec![
            mapping("req-1", "c-1", true),
            mapping("req-1", "c-2", false),
        ];
        let coverage = MappingEngine::requirement_coverage("req-1", "tenant-1", &mappings);
        assert!((coverage - 0.5).abs() < 1e-9);
    }
}
