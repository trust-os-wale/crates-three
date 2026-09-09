//! Policy DSL crate for Trust OS.
//!
//! Provides a domain-specific language for expressing access control,
//! compliance, and governance policies with structured evaluation.

use common::errors::{GrcError, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A compiled policy ready for evaluation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompiledPolicy {
    pub id: String,
    pub name: String,
    pub version: u32,
    pub effect: PolicyEffect,
    pub conditions: Vec<PolicyCondition>,
    pub obligations: Vec<String>,
    pub metadata: HashMap<String, String>,
}

/// Policy effect — allow or deny
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum PolicyEffect {
    Allow,
    Deny,
}

/// A single policy condition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyCondition {
    pub field: String,
    pub operator: PolicyOperator,
    pub value: PolicyValue,
    pub logic: Option<LogicOperator>,
}

/// Operators for condition evaluation
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum PolicyOperator {
    Equals,
    NotEquals,
    GreaterThan,
    LessThan,
    GreaterOrEqual,
    LessOrEqual,
    In,
    NotIn,
    Contains,
    NotContains,
    Matches,
    Exists,
    NotExists,
}

/// Logic operators for combining conditions
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum LogicOperator {
    And,
    Or,
}

/// Policy value types
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum PolicyValue {
    String(String),
    Number(f64),
    Boolean(bool),
    List(Vec<String>),
    Map(HashMap<String, String>),
}

/// Request context for policy evaluation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRequest {
    pub subject: HashMap<String, PolicyValue>,
    pub resource: HashMap<String, PolicyValue>,
    pub action: String,
    pub context: HashMap<String, PolicyValue>,
    pub environment: HashMap<String, PolicyValue>,
}

/// Policy evaluation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyDecision {
    pub allowed: bool,
    pub reason: String,
    pub obligations: Vec<String>,
    pub policy_id: String,
    pub evaluated_at: chrono::DateTime<chrono::Utc>,
}

/// Policy engine — evaluates policies against requests
pub struct PolicyEngine {
    policies: Vec<CompiledPolicy>,
}

impl PolicyEngine {
    pub fn new() -> Self {
        Self {
            policies: Vec::new(),
        }
    }

    /// Load policies from a JSON string
    pub fn load_policies(&mut self, json: &str) -> Result<()> {
        let policies: Vec<CompiledPolicy> = serde_json::from_str(json).map_err(|e| {
            GrcError::InvalidPolicyExpression(format!("Failed to parse policies: {}", e))
        })?;
        self.policies.extend(policies);
        Ok(())
    }

    /// Add a single compiled policy
    pub fn add_policy(&mut self, policy: CompiledPolicy) {
        self.policies.push(policy);
    }

    /// Evaluate all policies against a request
    pub fn evaluate(&self, request: &PolicyRequest) -> Result<PolicyDecision> {
        let mut last_decision = PolicyDecision {
            allowed: false,
            reason: "No matching policy".to_string(),
            obligations: Vec::new(),
            policy_id: String::new(),
            evaluated_at: chrono::Utc::now(),
        };

        for policy in &self.policies {
            if self.evaluate_conditions(&policy.conditions, request)? {
                last_decision = PolicyDecision {
                    allowed: policy.effect == PolicyEffect::Allow,
                    reason: format!("Policy '{}' matched", policy.name),
                    obligations: policy.obligations.clone(),
                    policy_id: policy.id.clone(),
                    evaluated_at: chrono::Utc::now(),
                };

                if policy.effect == PolicyEffect::Deny {
                    return Ok(last_decision);
                }
            }
        }

        Ok(last_decision)
    }

    /// Evaluate a set of conditions against a request
    fn evaluate_conditions(
        &self,
        conditions: &[PolicyCondition],
        request: &PolicyRequest,
    ) -> Result<bool> {
        if conditions.is_empty() {
            return Ok(true);
        }

        let mut results = Vec::new();

        for condition in conditions {
            let result = self.evaluate_condition(condition, request)?;
            results.push((
                result,
                condition.logic.clone().unwrap_or(LogicOperator::And),
            ));
        }

        if results.is_empty() {
            return Ok(true);
        }

        let mut final_result = results[0].0;
        for i in 1..results.len() {
            match results[i].1 {
                LogicOperator::And => final_result = final_result && results[i].0,
                LogicOperator::Or => final_result = final_result || results[i].0,
            }
        }

        Ok(final_result)
    }

    /// Evaluate a single condition
    fn evaluate_condition(
        &self,
        condition: &PolicyCondition,
        request: &PolicyRequest,
    ) -> Result<bool> {
        let field_value = self.resolve_field(&condition.field, request);

        match (&field_value, &condition.value) {
            (None, PolicyValue::Boolean(false)) => Ok(true),
            (None, _) => Ok(false),
            (Some(val), target) => self.compare_values(val, &condition.operator, target),
        }
    }

    /// Resolve a field path from the request context
    fn resolve_field(&self, field: &str, request: &PolicyRequest) -> Option<PolicyValue> {
        let parts: Vec<&str> = field.split('.').collect();
        if parts.is_empty() {
            return None;
        }

        let map = match parts[0] {
            "subject" => &request.subject,
            "resource" => &request.resource,
            "context" => &request.context,
            "environment" => &request.environment,
            _ => return None,
        };

        if parts.len() == 1 {
            return None;
        }

        map.get(parts[1]).cloned()
    }

    /// Compare two values using an operator
    fn compare_values(
        &self,
        left: &PolicyValue,
        operator: &PolicyOperator,
        right: &PolicyValue,
    ) -> Result<bool> {
        match operator {
            PolicyOperator::Equals => Ok(left == right),
            PolicyOperator::NotEquals => Ok(left != right),
            PolicyOperator::GreaterThan => Ok(self.compare_numeric(left, right, |a, b| a > b)),
            PolicyOperator::LessThan => Ok(self.compare_numeric(left, right, |a, b| a < b)),
            PolicyOperator::GreaterOrEqual => Ok(self.compare_numeric(left, right, |a, b| a >= b)),
            PolicyOperator::LessOrEqual => Ok(self.compare_numeric(left, right, |a, b| a <= b)),
            PolicyOperator::In => {
                if let (PolicyValue::String(s), PolicyValue::List(list)) = (left, right) {
                    Ok(list.contains(s))
                } else {
                    Ok(false)
                }
            }
            PolicyOperator::NotIn => {
                if let (PolicyValue::String(s), PolicyValue::List(list)) = (left, right) {
                    Ok(!list.contains(s))
                } else {
                    Ok(true)
                }
            }
            PolicyOperator::Contains => {
                if let (PolicyValue::String(haystack), PolicyValue::String(needle)) = (left, right)
                {
                    Ok(haystack.contains(needle))
                } else {
                    Ok(false)
                }
            }
            PolicyOperator::NotContains => {
                if let (PolicyValue::String(haystack), PolicyValue::String(needle)) = (left, right)
                {
                    Ok(!haystack.contains(needle))
                } else {
                    Ok(true)
                }
            }
            PolicyOperator::Matches => {
                if let (PolicyValue::String(s), PolicyValue::String(pattern)) = (left, right) {
                    let re = regex::Regex::new(pattern).map_err(|e| {
                        GrcError::InvalidPolicyExpression(format!("Invalid regex: {}", e))
                    })?;
                    Ok(re.is_match(s))
                } else {
                    Ok(false)
                }
            }
            PolicyOperator::Exists => Ok(true),
            PolicyOperator::NotExists => Ok(false),
        }
    }

    /// Compare numeric values
    fn compare_numeric(
        &self,
        left: &PolicyValue,
        right: &PolicyValue,
        op: impl Fn(f64, f64) -> bool,
    ) -> bool {
        match (left, right) {
            (PolicyValue::Number(a), PolicyValue::Number(b)) => op(*a, *b),
            (PolicyValue::String(a), PolicyValue::Number(b)) => {
                if let Ok(a_num) = a.parse::<f64>() {
                    op(a_num, *b)
                } else {
                    false
                }
            }
            _ => false,
        }
    }
}

impl Default for PolicyEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_policy_engine_allow() {
        let mut engine = PolicyEngine::new();
        let policy = CompiledPolicy {
            id: "test-1".into(),
            name: "Allow Admin".into(),
            version: 1,
            effect: PolicyEffect::Allow,
            conditions: vec![PolicyCondition {
                field: "subject.role".into(),
                operator: PolicyOperator::Equals,
                value: PolicyValue::String("admin".into()),
                logic: None,
            }],
            obligations: Vec::new(),
            metadata: HashMap::new(),
        };
        engine.add_policy(policy);

        let mut request = PolicyRequest {
            subject: HashMap::new(),
            resource: HashMap::new(),
            action: "read".into(),
            context: HashMap::new(),
            environment: HashMap::new(),
        };
        request
            .subject
            .insert("role".into(), PolicyValue::String("admin".into()));

        let decision = engine.evaluate(&request).unwrap();
        assert!(decision.allowed);
    }

    #[test]
    fn test_policy_engine_deny() {
        let mut engine = PolicyEngine::new();
        let policy = CompiledPolicy {
            id: "test-2".into(),
            name: "Deny Guest".into(),
            version: 1,
            effect: PolicyEffect::Deny,
            conditions: vec![PolicyCondition {
                field: "subject.role".into(),
                operator: PolicyOperator::Equals,
                value: PolicyValue::String("guest".into()),
                logic: None,
            }],
            obligations: Vec::new(),
            metadata: HashMap::new(),
        };
        engine.add_policy(policy);

        let mut request = PolicyRequest {
            subject: HashMap::new(),
            resource: HashMap::new(),
            action: "write".into(),
            context: HashMap::new(),
            environment: HashMap::new(),
        };
        request
            .subject
            .insert("role".into(), PolicyValue::String("guest".into()));

        let decision = engine.evaluate(&request).unwrap();
        assert!(!decision.allowed);
    }

    #[test]
    fn test_policy_engine_no_match() {
        let engine = PolicyEngine::new();
        let request = PolicyRequest {
            subject: HashMap::new(),
            resource: HashMap::new(),
            action: "read".into(),
            context: HashMap::new(),
            environment: HashMap::new(),
        };

        let decision = engine.evaluate(&request).unwrap();
        assert!(!decision.allowed);
    }

    #[test]
    fn test_policy_condition_in_list() {
        let mut engine = PolicyEngine::new();
        let policy = CompiledPolicy {
            id: "test-3".into(),
            name: "Allow List".into(),
            version: 1,
            effect: PolicyEffect::Allow,
            conditions: vec![PolicyCondition {
                field: "subject.role".into(),
                operator: PolicyOperator::In,
                value: PolicyValue::List(vec!["admin".into(), "manager".into(), "viewer".into()]),
                logic: None,
            }],
            obligations: Vec::new(),
            metadata: HashMap::new(),
        };
        engine.add_policy(policy);

        let mut request = PolicyRequest {
            subject: HashMap::new(),
            resource: HashMap::new(),
            action: "read".into(),
            context: HashMap::new(),
            environment: HashMap::new(),
        };
        request
            .subject
            .insert("role".into(), PolicyValue::String("manager".into()));

        let decision = engine.evaluate(&request).unwrap();
        assert!(decision.allowed);
    }

    #[test]
    fn test_policy_condition_regex() {
        let mut engine = PolicyEngine::new();
        let policy = CompiledPolicy {
            id: "test-4".into(),
            name: "Regex Match".into(),
            version: 1,
            effect: PolicyEffect::Allow,
            conditions: vec![PolicyCondition {
                field: "resource.path".into(),
                operator: PolicyOperator::Matches,
                value: PolicyValue::String("^/api/v[0-9]+/.*".into()),
                logic: None,
            }],
            obligations: Vec::new(),
            metadata: HashMap::new(),
        };
        engine.add_policy(policy);

        let mut request = PolicyRequest {
            subject: HashMap::new(),
            resource: HashMap::new(),
            action: "read".into(),
            context: HashMap::new(),
            environment: HashMap::new(),
        };
        request
            .resource
            .insert("path".into(), PolicyValue::String("/api/v2/users".into()));

        let decision = engine.evaluate(&request).unwrap();
        assert!(decision.allowed);
    }
}
