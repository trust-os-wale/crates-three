//! Compliance engine crate for Trust OS.
//!
//! Provides compliance rule evaluation, gap analysis, and remediation
//! tracking for GRC workflows.

pub mod evaluation;
pub mod remediation;
pub mod rules;

pub use evaluation::*;
pub use remediation::*;
pub use rules::*;

use common::errors::{GrcError, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Compliance status for controls
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ControlStatus {
    Implemented,
    PartiallyImplemented,
    NotImplemented,
    NotApplicable,
}

/// A compliance control
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceControl {
    pub id: String,
    pub name: String,
    pub description: String,
    pub framework_id: String,
    pub requirement_id: String,
    pub control_type: ControlType,
    pub status: ControlStatus,
    pub evidence_ids: Vec<String>,
    pub owner: Option<String>,
    pub metadata: HashMap<String, String>,
}

/// Types of compliance controls
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ControlType {
    Preventive,
    Detective,
    Corrective,
    Compensating,
}

/// Compliance evaluation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceResult {
    pub control_id: String,
    pub status: ControlStatus,
    pub score: f64,
    pub gaps: Vec<String>,
    pub recommendations: Vec<String>,
}

/// Gap analysis result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GapAnalysis {
    pub framework_id: String,
    pub tenant_id: String,
    pub total_controls: usize,
    pub implemented: usize,
    pub partially_implemented: usize,
    pub not_implemented: usize,
    pub gaps: Vec<ComplianceGap>,
    pub overall_score: f64,
    pub analyzed_at: chrono::DateTime<chrono::Utc>,
}

/// A specific compliance gap
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceGap {
    pub control_id: String,
    pub control_name: String,
    pub description: String,
    pub severity: GapSeverity,
    pub remediation_steps: Vec<String>,
}

/// Gap severity
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum GapSeverity {
    Low,
    Medium,
    High,
    Critical,
}

/// Compliance engine — evaluates controls and performs gap analysis
pub struct ComplianceEngine {
    controls: HashMap<String, ComplianceControl>,
}

impl ComplianceEngine {
    pub fn new() -> Self {
        Self {
            controls: HashMap::new(),
        }
    }

    pub fn add_control(&mut self, control: ComplianceControl) {
        self.controls.insert(control.id.clone(), control);
    }

    pub fn get_control(&self, id: &str) -> Option<&ComplianceControl> {
        self.controls.get(id)
    }

    pub fn evaluate_control(&self, control_id: &str) -> Result<ComplianceResult> {
        let control = self
            .controls
            .get(control_id)
            .ok_or_else(|| GrcError::ControlNotFound(control_id.to_string()))?;

        let (score, gaps, recommendations) = match control.status {
            ControlStatus::Implemented => (1.0, vec![], vec![]),
            ControlStatus::PartiallyImplemented => (
                0.5,
                vec![format!("Control '{}' partially implemented", control.name)],
                vec![format!("Complete implementation of {}", control.name)],
            ),
            ControlStatus::NotImplemented => (
                0.0,
                vec![format!("Control '{}' not implemented", control.name)],
                vec![
                    format!("Implement {}", control.name),
                    format!("Assign owner for {}", control.name),
                ],
            ),
            ControlStatus::NotApplicable => (1.0, vec![], vec![]),
        };

        Ok(ComplianceResult {
            control_id: control_id.to_string(),
            status: control.status.clone(),
            score,
            gaps,
            recommendations,
        })
    }

    pub fn gap_analysis(&self, framework_id: &str, tenant_id: &str) -> GapAnalysis {
        let framework_controls: Vec<&ComplianceControl> = self
            .controls
            .values()
            .filter(|c| c.framework_id == framework_id)
            .collect();

        let total = framework_controls.len();
        let implemented = framework_controls
            .iter()
            .filter(|c| c.status == ControlStatus::Implemented)
            .count();
        let partial = framework_controls
            .iter()
            .filter(|c| c.status == ControlStatus::PartiallyImplemented)
            .count();
        let not_impl = framework_controls
            .iter()
            .filter(|c| c.status == ControlStatus::NotImplemented)
            .count();

        let gaps: Vec<ComplianceGap> = framework_controls
            .iter()
            .filter(|c| {
                c.status == ControlStatus::PartiallyImplemented
                    || c.status == ControlStatus::NotImplemented
            })
            .map(|c| ComplianceGap {
                control_id: c.id.clone(),
                control_name: c.name.clone(),
                description: c.description.clone(),
                severity: if c.status == ControlStatus::NotImplemented {
                    GapSeverity::High
                } else {
                    GapSeverity::Medium
                },
                remediation_steps: vec![
                    format!("Review control requirements for {}", c.name),
                    format!("Implement missing controls for {}", c.name),
                    format!("Document evidence for {}", c.name),
                ],
            })
            .collect();

        let overall_score = if total > 0 {
            (implemented as f64 + (partial as f64 * 0.5)) / total as f64
        } else {
            0.0
        };

        GapAnalysis {
            framework_id: framework_id.to_string(),
            tenant_id: tenant_id.to_string(),
            total_controls: total,
            implemented,
            partially_implemented: partial,
            not_implemented: not_impl,
            gaps,
            overall_score,
            analyzed_at: chrono::Utc::now(),
        }
    }

    pub fn controls_for_framework(&self, framework_id: &str) -> Vec<&ComplianceControl> {
        self.controls
            .values()
            .filter(|c| c.framework_id == framework_id)
            .collect()
    }
}

impl Default for ComplianceEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_controls() -> Vec<ComplianceControl> {
        vec![
            ComplianceControl {
                id: "ctrl-1".into(),
                name: "Access Control".into(),
                description: "Implement role-based access control".into(),
                framework_id: "soc2".into(),
                requirement_id: "cc6".into(),
                control_type: ControlType::Preventive,
                status: ControlStatus::Implemented,
                evidence_ids: vec!["ev-1".into()],
                owner: Some("admin".into()),
                metadata: HashMap::new(),
            },
            ComplianceControl {
                id: "ctrl-2".into(),
                name: "Encryption".into(),
                description: "Encrypt data at rest and in transit".into(),
                framework_id: "soc2".into(),
                requirement_id: "cc6".into(),
                control_type: ControlType::Preventive,
                status: ControlStatus::PartiallyImplemented,
                evidence_ids: vec![],
                owner: Some("admin".into()),
                metadata: HashMap::new(),
            },
            ComplianceControl {
                id: "ctrl-3".into(),
                name: "Audit Logging".into(),
                description: "Maintain audit logs".into(),
                framework_id: "soc2".into(),
                requirement_id: "cc7".into(),
                control_type: ControlType::Detective,
                status: ControlStatus::NotImplemented,
                evidence_ids: vec![],
                owner: None,
                metadata: HashMap::new(),
            },
        ]
    }

    #[test]
    fn test_gap_analysis() {
        let mut engine = ComplianceEngine::new();
        for control in test_controls() {
            engine.add_control(control);
        }

        let analysis = engine.gap_analysis("soc2", "tenant-1");
        assert_eq!(analysis.total_controls, 3);
        assert_eq!(analysis.implemented, 1);
        assert_eq!(analysis.partially_implemented, 1);
        assert_eq!(analysis.not_implemented, 1);
        assert!(analysis.overall_score > 0.0);
        assert_eq!(analysis.gaps.len(), 2);
    }

    #[test]
    fn test_evaluate_control() {
        let mut engine = ComplianceEngine::new();
        engine.add_control(ComplianceControl {
            id: "ctrl-1".into(),
            name: "Test".into(),
            description: "Test control".into(),
            framework_id: "test".into(),
            requirement_id: "req-1".into(),
            control_type: ControlType::Preventive,
            status: ControlStatus::Implemented,
            evidence_ids: vec![],
            owner: None,
            metadata: HashMap::new(),
        });

        let result = engine.evaluate_control("ctrl-1").unwrap();
        assert_eq!(result.score, 1.0);
        assert!(result.gaps.is_empty());
    }
}
