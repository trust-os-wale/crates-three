use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceRule {
    pub id: String,
    pub name: String,
    pub description: String,
    pub framework_id: String,
    pub rule_expression: String,
    pub severity: RuleSeverity,
    pub auto_remediate: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum RuleSeverity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleEvaluation {
    pub rule_id: String,
    pub passed: bool,
    pub message: String,
    pub evaluated_at: chrono::DateTime<chrono::Utc>,
}

pub struct RuleEngine {
    rules: Vec<ComplianceRule>,
}

impl RuleEngine {
    pub fn new() -> Self {
        Self { rules: Vec::new() }
    }

    pub fn add_rule(&mut self, rule: ComplianceRule) {
        self.rules.push(rule);
    }

    pub fn evaluate(
        &self,
        framework_id: &str,
        context: &HashMap<String, String>,
    ) -> Vec<RuleEvaluation> {
        self.rules
            .iter()
            .filter(|r| r.framework_id == framework_id)
            .map(|rule| {
                let passed = self.evaluate_expression(&rule.rule_expression, context);
                RuleEvaluation {
                    rule_id: rule.id.clone(),
                    passed,
                    message: if passed {
                        format!("Rule '{}' passed", rule.name)
                    } else {
                        format!("Rule '{}' failed", rule.name)
                    },
                    evaluated_at: chrono::Utc::now(),
                }
            })
            .collect()
    }

    fn evaluate_expression(&self, expression: &str, context: &HashMap<String, String>) -> bool {
        if let Some((key, expected)) = expression.split_once('=') {
            context
                .get(key.trim())
                .map(|v| v == expected.trim())
                .unwrap_or(false)
        } else {
            context.contains_key(expression.trim())
        }
    }

    pub fn rules_for_framework(&self, framework_id: &str) -> Vec<&ComplianceRule> {
        self.rules
            .iter()
            .filter(|r| r.framework_id == framework_id)
            .collect()
    }
}

impl Default for RuleEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rule_evaluation() {
        let mut engine = RuleEngine::new();
        engine.add_rule(ComplianceRule {
            id: "r1".into(),
            name: "Encryption".into(),
            description: "Must be encrypted".into(),
            framework_id: "soc2".into(),
            rule_expression: "encryption = enabled".into(),
            severity: RuleSeverity::High,
            auto_remediate: false,
        });

        let mut context = HashMap::new();
        context.insert("encryption".into(), "enabled".into());

        let results = engine.evaluate("soc2", &context);
        assert_eq!(results.len(), 1);
        assert!(results[0].passed);
    }

    #[test]
    fn test_rule_failure() {
        let mut engine = RuleEngine::new();
        engine.add_rule(ComplianceRule {
            id: "r1".into(),
            name: "MFA".into(),
            description: "Must have MFA".into(),
            framework_id: "soc2".into(),
            rule_expression: "mfa = required".into(),
            severity: RuleSeverity::Critical,
            auto_remediate: false,
        });

        let context = HashMap::new();
        let results = engine.evaluate("soc2", &context);
        assert!(!results[0].passed);
    }
}
