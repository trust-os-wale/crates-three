use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceRule {
    pub id: String,
    pub framework_id: String,
    pub requirement_id: String,
    pub rule_type: RuleType,
    pub expression: String,
    pub description: String,
    pub severity: RuleSeverity,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum RuleType {
    Structural,
    Behavioral,
    Configuration,
    DataQuality,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum RuleSeverity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleEvaluationResult {
    pub rule_id: String,
    pub passed: bool,
    pub message: String,
    pub evidence: Vec<String>,
    pub evaluated_at: chrono::DateTime<chrono::Utc>,
}

pub struct ComplianceRuleEngine {
    rules: Vec<ComplianceRule>,
}

impl ComplianceRuleEngine {
    pub fn new() -> Self {
        Self { rules: Vec::new() }
    }

    pub fn add_rule(&mut self, rule: ComplianceRule) {
        self.rules.push(rule);
    }

    pub fn evaluate_rules(
        &self,
        framework_id: &str,
        context: &HashMap<String, String>,
    ) -> Vec<RuleEvaluationResult> {
        self.rules
            .iter()
            .filter(|r| r.framework_id == framework_id)
            .map(|rule| self.evaluate_rule(rule, context))
            .collect()
    }

    fn evaluate_rule(
        &self,
        rule: &ComplianceRule,
        context: &HashMap<String, String>,
    ) -> RuleEvaluationResult {
        let passed = match rule.rule_type {
            RuleType::Structural => {
                let required_keys: Vec<&str> =
                    rule.expression.split(',').map(|s| s.trim()).collect();
                required_keys.iter().all(|key| context.contains_key(*key))
            }
            RuleType::Configuration => {
                if let Some((key, expected)) = rule.expression.split_once('=') {
                    context
                        .get(key.trim())
                        .map(|v| v == expected.trim())
                        .unwrap_or(false)
                } else {
                    false
                }
            }
            RuleType::DataQuality => {
                if let Some((key, min_len)) = rule.expression.split_once(">=") {
                    context
                        .get(key.trim())
                        .map(|v| v.len() >= min_len.trim().parse::<usize>().unwrap_or(0))
                        .unwrap_or(false)
                } else {
                    true
                }
            }
            RuleType::Behavioral => true,
        };

        RuleEvaluationResult {
            rule_id: rule.id.clone(),
            passed,
            message: if passed {
                format!("Rule '{}' passed", rule.id)
            } else {
                format!("Rule '{}' failed: {}", rule.id, rule.description)
            },
            evidence: Vec::new(),
            evaluated_at: chrono::Utc::now(),
        }
    }

    pub fn compliance_score(&self, framework_id: &str, context: &HashMap<String, String>) -> f64 {
        let results = self.evaluate_rules(framework_id, context);
        if results.is_empty() {
            return 1.0;
        }
        let passed = results.iter().filter(|r| r.passed).count();
        passed as f64 / results.len() as f64
    }
}

impl Default for ComplianceRuleEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_structural_rule() {
        let mut engine = ComplianceRuleEngine::new();
        engine.add_rule(ComplianceRule {
            id: "r1".into(),
            framework_id: "gdpr".into(),
            requirement_id: "art-5".into(),
            rule_type: RuleType::Structural,
            expression: "data_classification,retention_policy".into(),
            description: "Must have data classification and retention policy".into(),
            severity: RuleSeverity::High,
        });

        let mut context = HashMap::new();
        context.insert("data_classification".into(), "confidential".into());
        context.insert("retention_policy".into(), "30days".into());

        let results = engine.evaluate_rules("gdpr", &context);
        assert_eq!(results.len(), 1);
        assert!(results[0].passed);
    }

    #[test]
    fn test_configuration_rule() {
        let mut engine = ComplianceRuleEngine::new();
        engine.add_rule(ComplianceRule {
            id: "r2".into(),
            framework_id: "soc2".into(),
            requirement_id: "cc6".into(),
            rule_type: RuleType::Configuration,
            expression: "encryption_enabled = true".into(),
            description: "Encryption must be enabled".into(),
            severity: RuleSeverity::Critical,
        });

        let mut context = HashMap::new();
        context.insert("encryption_enabled".into(), "true".into());

        let results = engine.evaluate_rules("soc2", &context);
        assert!(results[0].passed);
    }

    #[test]
    fn test_compliance_score() {
        let mut engine = ComplianceRuleEngine::new();
        engine.add_rule(ComplianceRule {
            id: "r1".into(),
            framework_id: "gdpr".into(),
            requirement_id: "art-5".into(),
            rule_type: RuleType::Structural,
            expression: "key1".into(),
            description: "Test".into(),
            severity: RuleSeverity::Low,
        });
        engine.add_rule(ComplianceRule {
            id: "r2".into(),
            framework_id: "gdpr".into(),
            requirement_id: "art-5".into(),
            rule_type: RuleType::Structural,
            expression: "key2".into(),
            description: "Test".into(),
            severity: RuleSeverity::Low,
        });

        let mut context = HashMap::new();
        context.insert("key1".into(), "val".into());

        let score = engine.compliance_score("gdpr", &context);
        assert!((score - 0.5).abs() < 0.01);
    }
}
