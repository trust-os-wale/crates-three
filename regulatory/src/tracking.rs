use crate::{ComplianceStatus, FrameworkId};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceTrackingEntry {
    pub id: String,
    pub framework_id: FrameworkId,
    pub tenant_id: String,
    pub requirement_id: String,
    pub status: ComplianceStatus,
    pub evidence_ids: Vec<String>,
    pub notes: String,
    pub last_reviewed: chrono::DateTime<chrono::Utc>,
    pub next_review: chrono::DateTime<chrono::Utc>,
    pub owner: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceTimeline {
    pub entries: Vec<ComplianceTrackingEntry>,
    pub summary: ComplianceSummary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceSummary {
    pub total_requirements: usize,
    pub compliant: usize,
    pub partially_compliant: usize,
    pub non_compliant: usize,
    pub not_assessed: usize,
}

pub struct ComplianceTracker {
    entries: Vec<ComplianceTrackingEntry>,
}

impl ComplianceTracker {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    pub fn add_entry(&mut self, entry: ComplianceTrackingEntry) {
        self.entries.push(entry);
    }

    pub fn get_entries_for_framework(
        &self,
        framework_id: &FrameworkId,
    ) -> Vec<&ComplianceTrackingEntry> {
        self.entries
            .iter()
            .filter(|e| &e.framework_id == framework_id)
            .collect()
    }

    pub fn get_entries_for_tenant(&self, tenant_id: &str) -> Vec<&ComplianceTrackingEntry> {
        self.entries
            .iter()
            .filter(|e| e.tenant_id == tenant_id)
            .collect()
    }

    pub fn summary_for_framework(&self, framework_id: &FrameworkId) -> ComplianceSummary {
        let entries = self.get_entries_for_framework(framework_id);
        let total = entries.len();
        let compliant = entries
            .iter()
            .filter(|e| e.status == ComplianceStatus::Compliant)
            .count();
        let partially_compliant = entries
            .iter()
            .filter(|e| e.status == ComplianceStatus::PartiallyCompliant)
            .count();
        let non_compliant = entries
            .iter()
            .filter(|e| e.status == ComplianceStatus::NonCompliant)
            .count();
        let not_assessed = entries
            .iter()
            .filter(|e| e.status == ComplianceStatus::NotAssessed)
            .count();

        ComplianceSummary {
            total_requirements: total,
            compliant,
            partially_compliant,
            non_compliant,
            not_assessed,
        }
    }

    pub fn compliance_score_for_framework(&self, framework_id: &FrameworkId) -> f64 {
        let summary = self.summary_for_framework(framework_id);
        if summary.total_requirements == 0 {
            return 0.0;
        }
        let weighted = summary.compliant as f64 + (summary.partially_compliant as f64 * 0.5);
        weighted / summary.total_requirements as f64
    }

    pub fn upcoming_reviews(&self, within_days: i64) -> Vec<&ComplianceTrackingEntry> {
        let deadline = chrono::Utc::now() + chrono::Duration::days(within_days);
        self.entries
            .iter()
            .filter(|e| e.next_review <= deadline)
            .collect()
    }
}

impl Default for ComplianceTracker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compliance_tracking() {
        let mut tracker = ComplianceTracker::new();
        tracker.add_entry(ComplianceTrackingEntry {
            id: "e1".into(),
            framework_id: "gdpr".into(),
            tenant_id: "t1".into(),
            requirement_id: "art-5".into(),
            status: ComplianceStatus::Compliant,
            evidence_ids: vec!["ev-1".into()],
            notes: "All controls met".into(),
            last_reviewed: chrono::Utc::now(),
            next_review: chrono::Utc::now() + chrono::Duration::days(90),
            owner: Some("admin".into()),
        });
        tracker.add_entry(ComplianceTrackingEntry {
            id: "e2".into(),
            framework_id: "gdpr".into(),
            tenant_id: "t1".into(),
            requirement_id: "art-17".into(),
            status: ComplianceStatus::PartiallyCompliant,
            evidence_ids: vec![],
            notes: "Missing erasure mechanism".into(),
            last_reviewed: chrono::Utc::now(),
            next_review: chrono::Utc::now() + chrono::Duration::days(30),
            owner: Some("admin".into()),
        });

        let summary = tracker.summary_for_framework(&"gdpr".into());
        assert_eq!(summary.total_requirements, 2);
        assert_eq!(summary.compliant, 1);
        assert_eq!(summary.partially_compliant, 1);

        let score = tracker.compliance_score_for_framework(&"gdpr".into());
        assert!((score - 0.75).abs() < 0.01);
    }
}
