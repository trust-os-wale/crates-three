//! Continuous compliance assessment domain types and aggregation logic.
//!
//! Per the Trust OS specification:
//! * Missing evidence is NOT non-compliance unless evidence is required
//!   (`evidence_required`); otherwise it yields NOT_ASSESSED.
//! * Uncertain legal interpretation yields REQUIRES_REVIEW and is never
//!   silently downgraded.
//! * Expired evidence yields EVIDENCE_EXPIRED and dominates the overall
//!   status (a claim of compliance cannot rest on stale evidence).
//! * NOT_APPLICABLE requirements are excluded from scoring.
//! * Compliance is distinct from trust: compliance never equals a trust
//!   score without further risk context.

use crate::ComplianceStatus;
use serde::{Deserialize, Serialize};

/// A single assessment run against one framework/regulation version.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceAssessment {
    pub id: String,
    pub tenant_id: String,
    pub organization_id: String,
    pub framework_id: Option<String>,
    pub framework_version_id: Option<String>,
    pub regulation_id: Option<String>,
    pub regulation_version_id: Option<String>,
    pub assessment_number: i64,
    pub status: ComplianceStatus,
    pub overall_score: f64,
    pub evidence_confidence: f64,
    pub trigger_source: String,
    pub assessed_at: chrono::DateTime<chrono::Utc>,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    pub determined_by: Option<String>,
    pub notes: Option<String>,
}

/// Result of assessing one requirement within an assessment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssessmentRequirementResult {
    pub id: String,
    pub assessment_id: String,
    pub requirement_id: String,
    pub status: ComplianceStatus,
    pub evidence_count: u32,
    pub evidence_confidence: f64,
    pub gaps: Vec<String>,
    pub findings: Vec<String>,
    pub evaluated_at: chrono::DateTime<chrono::Utc>,
}

/// Aggregated posture summary.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AssessmentSummary {
    pub total: usize,
    pub compliant: usize,
    pub partially_compliant: usize,
    pub non_compliant: usize,
    pub not_assessed: usize,
    pub not_applicable: usize,
    pub requires_review: usize,
    pub evidence_expired: usize,
    pub score: f64,
    pub status: ComplianceStatus,
}

impl Default for AssessmentSummary {
    fn default() -> Self {
        Self {
            total: 0,
            compliant: 0,
            partially_compliant: 0,
            non_compliant: 0,
            not_assessed: 0,
            not_applicable: 0,
            requires_review: 0,
            evidence_expired: 0,
            score: 0.0,
            status: ComplianceStatus::NotAssessed,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FindingSeverity {
    Critical,
    High,
    Medium,
    Low,
    Informational,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FindingStatus {
    Open,
    InProgress,
    Resolved,
    Accepted,
    Mitigated,
    Closed,
}

/// A compliance finding (gap) discovered during assessment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceFinding {
    pub id: String,
    pub tenant_id: String,
    pub assessment_id: Option<String>,
    pub requirement_id: Option<String>,
    pub title: String,
    pub description: String,
    pub severity: FindingSeverity,
    pub status: FindingStatus,
    pub evidence_ids: Vec<String>,
    pub remediation_ids: Vec<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ExceptionStatus {
    Requested,
    Approved,
    Expired,
    Revoked,
    Denied,
}

/// A formally accepted deviation from a requirement.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceException {
    pub id: String,
    pub tenant_id: String,
    pub organization_id: String,
    pub requirement_id: Option<String>,
    pub control_id: Option<String>,
    pub reason: String,
    pub justification: String,
    pub risk_acceptance: Option<String>,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    pub status: ExceptionStatus,
    pub approved_by: Option<String>,
    pub approved_at: Option<chrono::DateTime<chrono::Utc>>,
}

impl ComplianceException {
    /// True when the exception is approved and not yet expired.
    pub fn is_active(&self, now: chrono::DateTime<chrono::Utc>) -> bool {
        self.status == ExceptionStatus::Approved
            && self.expires_at.map(|e| now <= e).unwrap_or(true)
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RiskLevel {
    Critical,
    High,
    Medium,
    Low,
}

/// Latest compliance posture snapshot for an organization.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompliancePosture {
    pub id: String,
    pub tenant_id: String,
    pub organization_id: String,
    pub assessed_at: chrono::DateTime<chrono::Utc>,
    pub overall_score: f64,
    pub status: ComplianceStatus,
    pub summary: AssessmentSummary,
    pub risk_level: RiskLevel,
}

impl RiskLevel {
    pub fn from_score(score: f64) -> Self {
        match score {
            s if s >= 0.9 => Self::Low,
            s if s >= 0.7 => Self::Medium,
            s if s >= 0.5 => Self::High,
            _ => Self::Critical,
        }
    }
}

/// Pure aggregation and status-derivation logic.
pub struct ComplianceAssessor;

impl ComplianceAssessor {
    /// Effective status of a single requirement result, applying the
    /// evidence policy.
    fn effective_status(
        result: &AssessmentRequirementResult,
        evidence_required: bool,
    ) -> ComplianceStatus {
        if result.status == ComplianceStatus::NotAssessed
            && evidence_required
            && result.evidence_count == 0
        {
            ComplianceStatus::NonCompliant
        } else {
            result.status
        }
    }

    /// Aggregate requirement results into a summary.
    pub fn summarize(
        results: &[AssessmentRequirementResult],
        evidence_required: bool,
    ) -> AssessmentSummary {
        let mut summary = AssessmentSummary::default();
        let mut weighted: f64 = 0.0;
        let mut scored: usize = 0;

        for result in results {
            let status = Self::effective_status(result, evidence_required);
            match status {
                ComplianceStatus::Compliant => {
                    summary.compliant += 1;
                    weighted += 1.0;
                    scored += 1;
                }
                ComplianceStatus::PartiallyCompliant => {
                    summary.partially_compliant += 1;
                    weighted += 0.5;
                    scored += 1;
                }
                ComplianceStatus::NonCompliant => {
                    summary.non_compliant += 1;
                    scored += 1;
                }
                ComplianceStatus::NotAssessed => summary.not_assessed += 1,
                ComplianceStatus::NotApplicable => summary.not_applicable += 1,
                ComplianceStatus::RequiresReview => {
                    summary.requires_review += 1;
                    scored += 1;
                }
                ComplianceStatus::EvidenceExpired => {
                    summary.evidence_expired += 1;
                    scored += 1;
                }
            }
        }

        summary.total = results.len();
        summary.score = if scored > 0 {
            weighted / scored as f64
        } else {
            0.0
        };
        summary.status = Self::overall_status(results, evidence_required);
        summary
    }

    /// Derive the overall status.
    ///
    /// Domination order: EVIDENCE_EXPIRED > REQUIRES_REVIEW > NON_COMPLIANT,
    /// then score-based, then NOT_ASSESSED when nothing was scored.
    pub fn overall_status(
        results: &[AssessmentRequirementResult],
        evidence_required: bool,
    ) -> ComplianceStatus {
        let statuses: Vec<ComplianceStatus> = results
            .iter()
            .map(|r| Self::effective_status(r, evidence_required))
            .collect();

        if statuses
            .iter()
            .any(|s| *s == ComplianceStatus::EvidenceExpired)
        {
            return ComplianceStatus::EvidenceExpired;
        }
        if statuses
            .iter()
            .any(|s| *s == ComplianceStatus::RequiresReview)
        {
            return ComplianceStatus::RequiresReview;
        }
        if statuses
            .iter()
            .any(|s| *s == ComplianceStatus::NonCompliant)
        {
            return ComplianceStatus::NonCompliant;
        }

        let scored = results
            .iter()
            .filter(|r| !r.status.is_passive())
            .filter(|r| {
                Self::effective_status(r, evidence_required) != ComplianceStatus::NotAssessed
            })
            .count();
        if scored == 0 {
            return ComplianceStatus::NotAssessed;
        }

        let summary = Self::summarize(results, evidence_required);
        if summary.score >= 0.9 {
            ComplianceStatus::Compliant
        } else if summary.score >= 0.5 {
            ComplianceStatus::PartiallyCompliant
        } else {
            ComplianceStatus::NonCompliant
        }
    }

    /// Build a posture snapshot from an assessment and its results.
    pub fn posture(
        tenant_id: &str,
        organization_id: &str,
        _assessment: &ComplianceAssessment,
        results: &[AssessmentRequirementResult],
        evidence_required: bool,
    ) -> CompliancePosture {
        let summary = Self::summarize(results, evidence_required);
        CompliancePosture {
            id: uuid::Uuid::new_v4().to_string(),
            tenant_id: tenant_id.to_string(),
            organization_id: organization_id.to_string(),
            assessed_at: chrono::Utc::now(),
            overall_score: summary.score,
            status: summary.status,
            risk_level: RiskLevel::from_score(summary.score),
            summary,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn result(
        requirement_id: &str,
        status: ComplianceStatus,
        evidence_count: u32,
    ) -> AssessmentRequirementResult {
        AssessmentRequirementResult {
            id: format!("res-{requirement_id}"),
            assessment_id: "as-1".to_string(),
            requirement_id: requirement_id.to_string(),
            status,
            evidence_count,
            evidence_confidence: if evidence_count > 0 { 0.9 } else { 0.0 },
            gaps: vec![],
            findings: vec![],
            evaluated_at: chrono::Utc::now(),
        }
    }

    #[test]
    fn test_missing_evidence_is_not_non_compliance_by_default() {
        let results = vec![result("r1", ComplianceStatus::NotAssessed, 0)];
        let summary = ComplianceAssessor::summarize(&results, false);
        assert_eq!(summary.status, ComplianceStatus::NotAssessed);
        assert_eq!(summary.not_assessed, 1);
    }

    #[test]
    fn test_missing_evidence_is_non_compliance_when_required() {
        let results = vec![result("r1", ComplianceStatus::NotAssessed, 0)];
        let summary = ComplianceAssessor::summarize(&results, true);
        assert_eq!(summary.status, ComplianceStatus::NonCompliant);
        assert_eq!(summary.non_compliant, 1);
    }

    #[test]
    fn test_evidence_expired_dominates() {
        let results = vec![
            result("r1", ComplianceStatus::EvidenceExpired, 1),
            result("r2", ComplianceStatus::Compliant, 1),
        ];
        assert_eq!(
            ComplianceAssessor::overall_status(&results, false),
            ComplianceStatus::EvidenceExpired
        );
    }

    #[test]
    fn test_requires_review_dominates() {
        let results = vec![
            result("r1", ComplianceStatus::RequiresReview, 1),
            result("r2", ComplianceStatus::NonCompliant, 0),
        ];
        assert_eq!(
            ComplianceAssessor::overall_status(&results, false),
            ComplianceStatus::RequiresReview
        );
    }

    #[test]
    fn test_not_applicable_excluded_from_score() {
        let results = vec![
            result("r1", ComplianceStatus::Compliant, 1),
            result("r2", ComplianceStatus::NotApplicable, 0),
        ];
        let summary = ComplianceAssessor::summarize(&results, false);
        assert!((summary.score - 1.0).abs() < 1e-9);
        assert_eq!(summary.status, ComplianceStatus::Compliant);
    }

    #[test]
    fn test_score_thresholds() {
        let half = ComplianceAssessor::summarize(
            &[
                result("r1", ComplianceStatus::Compliant, 1),
                result("r2", ComplianceStatus::NonCompliant, 0),
            ],
            false,
        );
        assert_eq!(half.status, ComplianceStatus::PartiallyCompliant);

        let low = ComplianceAssessor::summarize(
            &[
                result("r1", ComplianceStatus::Compliant, 1),
                result("r2", ComplianceStatus::NonCompliant, 0),
                result("r3", ComplianceStatus::NonCompliant, 0),
            ],
            false,
        );
        assert_eq!(low.status, ComplianceStatus::NonCompliant);
    }

    #[test]
    fn test_exception_active_window() {
        let exception = ComplianceException {
            id: "e1".to_string(),
            tenant_id: "tenant-1".to_string(),
            organization_id: "org-1".to_string(),
            requirement_id: Some("r1".to_string()),
            control_id: None,
            reason: "Legacy system".to_string(),
            justification: "Migrations planned".to_string(),
            risk_acceptance: None,
            expires_at: Some(chrono::Utc::now() + chrono::Duration::days(30)),
            status: ExceptionStatus::Approved,
            approved_by: Some("compliance-officer".to_string()),
            approved_at: Some(chrono::Utc::now()),
        };
        assert!(exception.is_active(chrono::Utc::now()));
    }
}
