//! Applicability engine.
//!
//! Determines whether a regulation, framework or requirement applies to an
//! organization. Decision values match the `applicability_decision` enum in
//! migration 005:
//!
//! * APPLICABLE — a deterministic rule matched.
//! * POTENTIALLY_APPLICABLE — no deterministic rule matched, but the
//!   organization context suggests possible applicability (conservative).
//! * NOT_APPLICABLE — a deterministic exclusion rule matched.
//! * REQUIRES_REVIEW — uncertain interpretation, advisory rule match, or
//!   insufficient context. Never decided silently.
//! * EXPIRED — the matching rule's effective window has ended.
//! * SUPERSEDED — the target has been superseded by a newer version.
//!
//! Deterministic rules decide; advisory rules never decide on their own.
//! AI-generated applicability signals are always treated as advisory.

use crate::RecordStatus;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ApplicabilityDecision {
    Applicable,
    PotentiallyApplicable,
    NotApplicable,
    RequiresReview,
    Expired,
    Superseded,
}

impl ApplicabilityDecision {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Applicable => "APPLICABLE",
            Self::PotentiallyApplicable => "POTENTIALLY_APPLICABLE",
            Self::NotApplicable => "NOT_APPLICABLE",
            Self::RequiresReview => "REQUIRES_REVIEW",
            Self::Expired => "EXPIRED",
            Self::Superseded => "SUPERSEDED",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ApplicabilityTarget {
    Regulation,
    Framework,
    Requirement,
}

/// Criteria block used by deterministic and advisory rules.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuleCriteria {
    pub jurisdictions: Vec<String>,
    pub industries: Vec<String>,
    pub activities: Vec<String>,
    pub organization_attributes: HashMap<String, String>,
}

impl RuleCriteria {
    pub fn is_empty(&self) -> bool {
        self.jurisdictions.is_empty()
            && self.industries.is_empty()
            && self.activities.is_empty()
            && self.organization_attributes.is_empty()
    }
}

/// An applicability rule. Deterministic rules decide; advisory rules
/// (including all AI-generated ones) only signal REQUIRES_REVIEW.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApplicabilityRule {
    pub id: String,
    pub tenant_id: String,
    pub target_type: ApplicabilityTarget,
    pub target_id: String,
    pub is_deterministic: bool,
    pub criteria: RuleCriteria,
    pub decision: ApplicabilityDecision,
    pub confidence: f64,
    pub reason: String,
    pub status: RecordStatus,
    pub effective_from: Option<chrono::DateTime<chrono::Utc>>,
    pub effective_to: Option<chrono::DateTime<chrono::Utc>>,
}

/// Organizational context snapshot used at assessment time.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OrganizationContext {
    pub organization_id: String,
    pub jurisdiction_ids: Vec<String>,
    pub industry_ids: Vec<String>,
    pub activity_ids: Vec<String>,
    pub attributes: HashMap<String, String>,
}

impl OrganizationContext {
    pub fn is_populated(&self) -> bool {
        !self.jurisdiction_ids.is_empty()
            || !self.industry_ids.is_empty()
            || !self.activity_ids.is_empty()
    }
}

/// Outcome of matching a single rule against context.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleMatch {
    Triggered(ApplicabilityDecision),
    NotTriggered,
    Inactive,
    OutOfWindow,
}

/// Recorded result of evaluating one target for one organization.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApplicabilityAssessment {
    pub id: String,
    pub tenant_id: String,
    pub organization_id: String,
    pub target_type: ApplicabilityTarget,
    pub target_id: String,
    pub decision: ApplicabilityDecision,
    pub confidence: f64,
    pub reason: String,
    pub criteria_snapshot: serde_json::Value,
    pub review_required: bool,
    pub review_reason: Option<String>,
    pub determined_at: chrono::DateTime<chrono::Utc>,
    pub rule_id: Option<String>,
}

pub struct ApplicabilityEngine;

impl ApplicabilityEngine {
    /// Match a single rule. `OutOfWindow` distinguishes expired rules from
    /// rules that are not yet effective.
    pub fn match_rule(
        rule: &ApplicabilityRule,
        context: &OrganizationContext,
        now: chrono::DateTime<chrono::Utc>,
    ) -> RuleMatch {
        if rule.status != RecordStatus::Active {
            return RuleMatch::Inactive;
        }
        if let Some(to) = rule.effective_to {
            if now > to {
                return RuleMatch::OutOfWindow;
            }
        }
        if let Some(from) = rule.effective_from {
            if now < from {
                return RuleMatch::OutOfWindow;
            }
        }

        let matched = rule.criteria.jurisdictions.is_empty()
            || rule
                .criteria
                .jurisdictions
                .iter()
                .any(|j| context.jurisdiction_ids.contains(j));
        let matched = matched
            && (rule.criteria.industries.is_empty()
                || rule
                    .criteria
                    .industries
                    .iter()
                    .any(|i| context.industry_ids.contains(i)));
        let matched = matched
            && (rule.criteria.activities.is_empty()
                || rule
                    .criteria
                    .activities
                    .iter()
                    .any(|a| context.activity_ids.contains(a)));
        let matched = matched
            && rule
                .criteria
                .organization_attributes
                .iter()
                .all(|(k, v)| context.attributes.get(k).map(|cv| cv == v).unwrap_or(false));

        if matched {
            RuleMatch::Triggered(rule.decision)
        } else {
            RuleMatch::NotTriggered
        }
    }

    /// Determine the applicability of a single target for an organization.
    ///
    /// Evaluation order:
    /// 1. Highest-confidence rules first.
    /// 2. A deterministic rule that triggers decides the outcome —
    ///    including explicit exclusions (NOT_APPLICABLE).
    /// 3. An advisory rule that triggers yields REQUIRES_REVIEW.
    /// 4. An expired rule yields EXPIRED.
    /// 5. No match + no context -> REQUIRES_REVIEW.
    /// 6. No match + populated context -> POTENTIALLY_APPLICABLE (reviewed).
    pub fn determine(
        target_type: ApplicabilityTarget,
        target_id: &str,
        tenant_id: &str,
        context: &OrganizationContext,
        rules: &[ApplicabilityRule],
        now: chrono::DateTime<chrono::Utc>,
    ) -> ApplicabilityAssessment {
        let mut candidates: Vec<&ApplicabilityRule> = rules
            .iter()
            .filter(|r| {
                r.tenant_id == tenant_id && r.target_type == target_type && r.target_id == target_id
            })
            .collect();
        candidates.sort_by(|a, b| {
            b.confidence
                .partial_cmp(&a.confidence)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        for rule in candidates {
            match Self::match_rule(rule, context, now) {
                RuleMatch::Inactive => continue,
                RuleMatch::NotTriggered => continue,
                RuleMatch::OutOfWindow => {
                    let expired = rule.effective_to.map(|to| now > to).unwrap_or(false);
                    let decision = if expired {
                        ApplicabilityDecision::Expired
                    } else {
                        ApplicabilityDecision::RequiresReview
                    };
                    let reason = if expired {
                        format!(
                            "Rule '{}' effective window has expired ({})",
                            rule.id,
                            rule.effective_to
                                .map(|t| t.to_rfc3339())
                                .unwrap_or_default()
                        )
                    } else {
                        format!(
                            "Rule '{}' is not yet effective (from {})",
                            rule.id,
                            rule.effective_from
                                .map(|f| f.to_rfc3339())
                                .unwrap_or_default()
                        )
                    };
                    return Self::assessment(
                        target_type,
                        target_id,
                        tenant_id,
                        context,
                        decision,
                        reason,
                        Some(rule.id.clone()),
                        rule.confidence,
                        expired,
                        Some("Rule outside its effective window".to_string()),
                    );
                }
                RuleMatch::Triggered(decision) => {
                    if rule.is_deterministic {
                        return Self::assessment(
                            target_type,
                            target_id,
                            tenant_id,
                            context,
                            decision,
                            format!("Deterministic rule '{}': {}", rule.id, rule.reason),
                            Some(rule.id.clone()),
                            rule.confidence,
                            false,
                            None,
                        );
                    }
                    // Advisory rules never decide: uncertain interpretation
                    // must surface for human review.
                    return Self::assessment(
                        target_type,
                        target_id,
                        tenant_id,
                        context,
                        ApplicabilityDecision::RequiresReview,
                        format!(
                            "Advisory rule '{}' suggests {:?} — requires human review",
                            rule.id,
                            decision.label()
                        ),
                        Some(rule.id.clone()),
                        rule.confidence,
                        true,
                        Some(format!(
                            "Non-deterministic rule suggests {}",
                            decision.label()
                        )),
                    );
                }
            }
        }

        if !context.is_populated() {
            Self::assessment(
                target_type,
                target_id,
                tenant_id,
                context,
                ApplicabilityDecision::RequiresReview,
                "Insufficient organizational context to determine applicability".to_string(),
                None,
                0.0,
                true,
                Some("Insufficient organizational context".to_string()),
            )
        } else {
            Self::assessment(
                target_type,
                target_id,
                tenant_id,
                context,
                ApplicabilityDecision::PotentiallyApplicable,
                "No deterministic rule matched — conservatively treated as potentially applicable"
                    .to_string(),
                None,
                0.0,
                true,
                Some("No deterministic rule matched".to_string()),
            )
        }
    }

    fn assessment(
        target_type: ApplicabilityTarget,
        target_id: &str,
        tenant_id: &str,
        context: &OrganizationContext,
        decision: ApplicabilityDecision,
        reason: String,
        rule_id: Option<String>,
        confidence: f64,
        review_required: bool,
        review_reason: Option<String>,
    ) -> ApplicabilityAssessment {
        ApplicabilityAssessment {
            id: uuid::Uuid::new_v4().to_string(),
            tenant_id: tenant_id.to_string(),
            organization_id: context.organization_id.clone(),
            target_type,
            target_id: target_id.to_string(),
            decision,
            confidence,
            reason,
            criteria_snapshot: serde_json::json!({
                "jurisdictions": context.jurisdiction_ids,
                "industries": context.industry_ids,
                "activities": context.activity_ids,
                "attributes": context.attributes,
            }),
            review_required,
            review_reason,
            determined_at: chrono::Utc::now(),
            rule_id,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn context() -> OrganizationContext {
        OrganizationContext {
            organization_id: "org-1".to_string(),
            jurisdiction_ids: vec!["de".to_string(), "eu".to_string()],
            industry_ids: vec!["finance".to_string()],
            activity_ids: vec!["payments".to_string()],
            attributes: HashMap::new(),
        }
    }

    fn rule(
        id: &str,
        decision: ApplicabilityDecision,
        deterministic: bool,
        jurisdictions: &[&str],
    ) -> ApplicabilityRule {
        ApplicabilityRule {
            id: id.to_string(),
            tenant_id: "tenant-1".to_string(),
            target_type: ApplicabilityTarget::Regulation,
            target_id: "reg-gdpr".to_string(),
            is_deterministic: deterministic,
            criteria: RuleCriteria {
                jurisdictions: jurisdictions.iter().map(|s| s.to_string()).collect(),
                industries: vec![],
                activities: vec![],
                organization_attributes: HashMap::new(),
            },
            decision,
            confidence: 1.0,
            reason: "test rule".to_string(),
            status: RecordStatus::Active,
            effective_from: None,
            effective_to: None,
        }
    }

    #[test]
    fn test_deterministic_match_is_applicable() {
        let rules = vec![rule("r1", ApplicabilityDecision::Applicable, true, &["eu"])];
        let result = ApplicabilityEngine::determine(
            ApplicabilityTarget::Regulation,
            "reg-gdpr",
            "tenant-1",
            &context(),
            &rules,
            chrono::Utc::now(),
        );
        assert_eq!(result.decision, ApplicabilityDecision::Applicable);
        assert!(!result.review_required);
    }

    #[test]
    fn test_explicit_exclusion_is_not_applicable() {
        let rules = vec![rule(
            "r2",
            ApplicabilityDecision::NotApplicable,
            true,
            &["us"],
        )];
        let result = ApplicabilityEngine::determine(
            ApplicabilityTarget::Regulation,
            "reg-gdpr",
            "tenant-1",
            &context(),
            &rules,
            chrono::Utc::now(),
        );
        assert_eq!(result.decision, ApplicabilityDecision::NotApplicable);
    }

    #[test]
    fn test_advisory_rule_never_decides() {
        let rules = vec![rule(
            "r3",
            ApplicabilityDecision::Applicable,
            false,
            &["eu"],
        )];
        let result = ApplicabilityEngine::determine(
            ApplicabilityTarget::Regulation,
            "reg-gdpr",
            "tenant-1",
            &context(),
            &rules,
            chrono::Utc::now(),
        );
        assert_eq!(result.decision, ApplicabilityDecision::RequiresReview);
        assert!(result.review_required);
    }

    #[test]
    fn test_expired_rule_is_expired() {
        let mut r = rule("r4", ApplicabilityDecision::Applicable, true, &["eu"]);
        r.effective_to = Some(
            chrono::DateTime::parse_from_rfc3339("2020-01-01T00:00:00Z")
                .unwrap()
                .with_timezone(&chrono::Utc),
        );
        let result = ApplicabilityEngine::determine(
            ApplicabilityTarget::Regulation,
            "reg-gdpr",
            "tenant-1",
            &context(),
            &[r],
            chrono::Utc::now(),
        );
        assert_eq!(result.decision, ApplicabilityDecision::Expired);
    }

    #[test]
    fn test_no_match_with_context_is_potentially_applicable() {
        let result = ApplicabilityEngine::determine(
            ApplicabilityTarget::Regulation,
            "reg-unknown",
            "tenant-1",
            &context(),
            &[],
            chrono::Utc::now(),
        );
        assert_eq!(
            result.decision,
            ApplicabilityDecision::PotentiallyApplicable
        );
        assert!(result.review_required);
    }

    #[test]
    fn test_no_context_requires_review() {
        let empty = OrganizationContext::default();
        let result = ApplicabilityEngine::determine(
            ApplicabilityTarget::Regulation,
            "reg-unknown",
            "tenant-1",
            &empty,
            &[],
            chrono::Utc::now(),
        );
        assert_eq!(result.decision, ApplicabilityDecision::RequiresReview);
    }
}
