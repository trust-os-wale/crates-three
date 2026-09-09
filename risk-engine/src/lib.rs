//! Risk engine crate for Trust OS.
//!
//! Provides risk calculation, scoring, and assessment capabilities
//! with configurable risk domains and scoring factors.

use common::errors::{GrcError, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Risk score between 0.0 (no risk) and 10.0 (critical risk)
pub type RiskScore = f64;

/// Risk domain identifier
pub type RiskDomainId = String;

/// Risk assessment result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskAssessment {
    pub id: String,
    pub tenant_id: String,
    pub domain: RiskDomainId,
    pub overall_score: RiskScore,
    pub factor_scores: HashMap<String, RiskScore>,
    pub risk_level: RiskLevel,
    pub mitigations: Vec<Mitigation>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub expires_at: chrono::DateTime<chrono::Utc>,
}

/// Risk levels derived from scores
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

impl RiskLevel {
    pub fn from_score(score: RiskScore) -> Self {
        match score {
            s if s < 2.0 => RiskLevel::Low,
            s if s < 5.0 => RiskLevel::Medium,
            s if s < 8.0 => RiskLevel::High,
            _ => RiskLevel::Critical,
        }
    }
}

/// Mitigation action for a risk
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Mitigation {
    pub id: String,
    pub description: String,
    pub priority: MitigationPriority,
    pub estimated_effort: String,
    pub estimated_cost: Option<f64>,
    pub owner: Option<String>,
    pub deadline: Option<chrono::DateTime<chrono::Utc>>,
}

/// Mitigation priority
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum MitigationPriority {
    Low,
    Medium,
    High,
    Urgent,
}

/// Risk domain definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskDomain {
    pub id: RiskDomainId,
    pub name: String,
    pub description: String,
    pub weight: f64,
    pub factors: Vec<RiskFactor>,
}

/// A factor that contributes to risk scoring
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskFactor {
    pub id: String,
    pub name: String,
    pub weight: f64,
    pub scoring_fn: String,
    pub description: String,
}

/// Risk engine — calculates and manages risk assessments
pub struct RiskEngine {
    domains: HashMap<RiskDomainId, RiskDomain>,
    assessments: Vec<RiskAssessment>,
}

impl RiskEngine {
    pub fn new() -> Self {
        Self {
            domains: HashMap::new(),
            assessments: Vec::new(),
        }
    }

    /// Register a risk domain
    pub fn register_domain(&mut self, domain: RiskDomain) {
        self.domains.insert(domain.id.clone(), domain);
    }

    /// Calculate risk score for a domain
    pub fn calculate_risk(
        &self,
        domain_id: &RiskDomainId,
        tenant_id: &str,
        factor_values: &HashMap<String, f64>,
    ) -> Result<RiskAssessment> {
        let domain = self.domains.get(domain_id).ok_or_else(|| {
            GrcError::RiskCalculationFailed(format!("Domain '{}' not found", domain_id))
        })?;

        let mut factor_scores = HashMap::new();
        let mut weighted_sum = 0.0;
        let mut total_weight = 0.0;

        for factor in &domain.factors {
            let value = factor_values.get(&factor.id).copied().unwrap_or(0.0);
            let score = (value * factor.weight).min(10.0);
            factor_scores.insert(factor.id.clone(), score);
            weighted_sum += score;
            total_weight += factor.weight;
        }

        let overall_score = if total_weight > 0.0 {
            (weighted_sum / total_weight).min(10.0)
        } else {
            0.0
        };

        let risk_level = RiskLevel::from_score(overall_score);

        let assessment = RiskAssessment {
            id: uuid::Uuid::new_v4().to_string(),
            tenant_id: tenant_id.to_string(),
            domain: domain_id.clone(),
            overall_score,
            factor_scores,
            risk_level,
            mitigations: Vec::new(),
            created_at: chrono::Utc::now(),
            expires_at: chrono::Utc::now() + chrono::Duration::hours(24),
        };

        Ok(assessment)
    }

    /// Get all assessments for a tenant
    pub fn get_assessments(&self, tenant_id: &str) -> Vec<&RiskAssessment> {
        self.assessments
            .iter()
            .filter(|a| a.tenant_id == tenant_id)
            .collect()
    }

    /// Store an assessment
    pub fn store_assessment(&mut self, assessment: RiskAssessment) {
        self.assessments.push(assessment);
    }

    /// Get risk level summary for a tenant
    pub fn get_risk_summary(&self, tenant_id: &str) -> RiskSummary {
        let assessments: Vec<&RiskAssessment> = self
            .assessments
            .iter()
            .filter(|a| a.tenant_id == tenant_id)
            .collect();

        let total = assessments.len();
        let critical = assessments
            .iter()
            .filter(|a| a.risk_level == RiskLevel::Critical)
            .count();
        let high = assessments
            .iter()
            .filter(|a| a.risk_level == RiskLevel::High)
            .count();
        let medium = assessments
            .iter()
            .filter(|a| a.risk_level == RiskLevel::Medium)
            .count();
        let low = assessments
            .iter()
            .filter(|a| a.risk_level == RiskLevel::Low)
            .count();

        let avg_score = if total > 0 {
            assessments.iter().map(|a| a.overall_score).sum::<f64>() / total as f64
        } else {
            0.0
        };

        RiskSummary {
            total_assessments: total,
            critical_count: critical,
            high_count: high,
            medium_count: medium,
            low_count: low,
            average_score: avg_score,
        }
    }
}

/// Risk summary for a tenant
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskSummary {
    pub total_assessments: usize,
    pub critical_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub low_count: usize,
    pub average_score: RiskScore,
}

impl Default for RiskEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_domain() -> RiskDomain {
        RiskDomain {
            id: "cyber".into(),
            name: "Cybersecurity Risk".into(),
            description: "Information security risks".into(),
            weight: 1.0,
            factors: vec![
                RiskFactor {
                    id: "vulnerabilities".into(),
                    name: "Vulnerability Count".into(),
                    weight: 0.4,
                    scoring_fn: "linear".into(),
                    description: "Number of known vulnerabilities".into(),
                },
                RiskFactor {
                    id: "patch_latency".into(),
                    name: "Patch Latency".into(),
                    weight: 0.3,
                    scoring_fn: "linear".into(),
                    description: "Days since patch available".into(),
                },
                RiskFactor {
                    id: "access_control".into(),
                    name: "Access Control".into(),
                    weight: 0.3,
                    scoring_fn: "linear".into(),
                    description: "Access control maturity".into(),
                },
            ],
        }
    }

    #[test]
    fn test_risk_calculation() {
        let mut engine = RiskEngine::new();
        engine.register_domain(test_domain());

        let mut factor_values = HashMap::new();
        factor_values.insert("vulnerabilities".into(), 7.0);
        factor_values.insert("patch_latency".into(), 5.0);
        factor_values.insert("access_control".into(), 3.0);

        let assessment = engine
            .calculate_risk(&"cyber".into(), "tenant-1", &factor_values)
            .unwrap();

        assert!(assessment.overall_score > 0.0);
        assert!(assessment.overall_score <= 10.0);
        assert_eq!(assessment.tenant_id, "tenant-1");
    }

    #[test]
    fn test_risk_level() {
        assert_eq!(RiskLevel::from_score(1.0), RiskLevel::Low);
        assert_eq!(RiskLevel::from_score(3.0), RiskLevel::Medium);
        assert_eq!(RiskLevel::from_score(6.0), RiskLevel::High);
        assert_eq!(RiskLevel::from_score(9.0), RiskLevel::Critical);
    }

    #[test]
    fn test_risk_summary() {
        let mut engine = RiskEngine::new();
        engine.register_domain(test_domain());

        let mut factor_values = HashMap::new();
        factor_values.insert("vulnerabilities".into(), 5.0);
        factor_values.insert("patch_latency".into(), 3.0);
        factor_values.insert("access_control".into(), 2.0);

        let assessment = engine
            .calculate_risk(&"cyber".into(), "tenant-1", &factor_values)
            .unwrap();
        engine.store_assessment(assessment);

        let summary = engine.get_risk_summary("tenant-1");
        assert_eq!(summary.total_assessments, 1);
        assert!(summary.average_score > 0.0);
    }

    #[test]
    fn test_domain_not_found() {
        let engine = RiskEngine::new();
        let result = engine.calculate_risk(&"nonexistent".into(), "tenant-1", &HashMap::new());
        assert!(result.is_err());
    }
}
