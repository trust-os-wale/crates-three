use crate::{ComplianceControl, ControlStatus};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvaluationInput {
    pub control_id: String,
    pub evidence: Vec<String>,
    pub configuration: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvaluationOutput {
    pub control_id: String,
    pub status: ControlStatus,
    pub score: f64,
    pub findings: Vec<String>,
    pub recommendations: Vec<String>,
}

pub struct ComplianceEvaluator;

impl ComplianceEvaluator {
    pub fn evaluate_control(
        input: &EvaluationInput,
        control: &ComplianceControl,
    ) -> EvaluationOutput {
        let mut findings = Vec::new();
        let mut recommendations = Vec::new();

        let has_evidence = !input.evidence.is_empty();
        let has_config = !input.configuration.is_empty();

        let (status, score) = match (has_evidence, has_config) {
            (true, true) => (ControlStatus::Implemented, 1.0),
            (true, false) => {
                findings.push("Missing configuration data".into());
                recommendations.push("Provide configuration evidence".into());
                (ControlStatus::PartiallyImplemented, 0.7)
            }
            (false, true) => {
                findings.push("Missing evidence documentation".into());
                recommendations.push("Collect and document evidence".into());
                (ControlStatus::PartiallyImplemented, 0.5)
            }
            (false, false) => {
                findings.push("No evidence or configuration provided".into());
                recommendations.push("Implement control and collect evidence".into());
                (ControlStatus::NotImplemented, 0.0)
            }
        };

        EvaluationOutput {
            control_id: control.id.clone(),
            status,
            score,
            findings,
            recommendations,
        }
    }

    pub fn batch_evaluate(
        inputs: &[EvaluationInput],
        controls: &[ComplianceControl],
    ) -> Vec<EvaluationOutput> {
        let control_map: HashMap<&str, &ComplianceControl> =
            controls.iter().map(|c| (c.id.as_str(), c)).collect();

        inputs
            .iter()
            .filter_map(|input| {
                control_map
                    .get(input.control_id.as_str())
                    .map(|control| Self::evaluate_control(input, control))
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ComplianceControl, ControlType};

    #[test]
    fn test_evaluate_implemented() {
        let input = EvaluationInput {
            control_id: "ctrl-1".into(),
            evidence: vec!["doc1.pdf".into()],
            configuration: HashMap::new(),
        };
        let control = ComplianceControl {
            id: "ctrl-1".into(),
            name: "Test".into(),
            description: "Test".into(),
            framework_id: "test".into(),
            requirement_id: "req-1".into(),
            control_type: ControlType::Preventive,
            status: ControlStatus::NotImplemented,
            evidence_ids: vec![],
            owner: None,
            metadata: HashMap::new(),
        };

        let output = ComplianceEvaluator::evaluate_control(&input, &control);
        assert_eq!(output.score, 0.7);
        assert_eq!(output.status, ControlStatus::PartiallyImplemented);
    }
}
