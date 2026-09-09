use common::errors::{GrcError, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemediationPlan {
    pub id: String,
    pub gap_id: String,
    pub control_id: String,
    pub title: String,
    pub description: String,
    pub steps: Vec<RemediationStep>,
    pub priority: RemediationPriority,
    pub owner: Option<String>,
    pub deadline: Option<chrono::DateTime<chrono::Utc>>,
    pub status: RemediationStatus,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemediationStep {
    pub order: u32,
    pub description: String,
    pub completed: bool,
    pub completed_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum RemediationPriority {
    Low,
    Medium,
    High,
    Urgent,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum RemediationStatus {
    NotStarted,
    InProgress,
    Completed,
    Blocked,
}

pub struct RemediationTracker {
    plans: Vec<RemediationPlan>,
}

impl RemediationTracker {
    pub fn new() -> Self {
        Self { plans: Vec::new() }
    }

    pub fn create_plan(&mut self, plan: RemediationPlan) {
        self.plans.push(plan);
    }

    pub fn get_plan(&self, id: &str) -> Option<&RemediationPlan> {
        self.plans.iter().find(|p| p.id == id)
    }

    pub fn update_step(&mut self, plan_id: &str, step_order: u32, completed: bool) -> Result<()> {
        let plan = self
            .plans
            .iter_mut()
            .find(|p| p.id == plan_id)
            .ok_or_else(|| GrcError::WorkflowNotFound(plan_id.to_string()))?;

        if let Some(step) = plan.steps.iter_mut().find(|s| s.order == step_order) {
            step.completed = completed;
            if completed {
                step.completed_at = Some(chrono::Utc::now());
            }
        }

        let all_complete = plan.steps.iter().all(|s| s.completed);
        if all_complete {
            plan.status = RemediationStatus::Completed;
        } else if plan.steps.iter().any(|s| s.completed) {
            plan.status = RemediationStatus::InProgress;
        }

        Ok(())
    }

    pub fn plans_for_tenant(&self, tenant_id: &str) -> Vec<&RemediationPlan> {
        self.plans
            .iter()
            .filter(|p| p.owner.as_deref() == Some(tenant_id))
            .collect()
    }

    pub fn overdue_plans(&self) -> Vec<&RemediationPlan> {
        let now = chrono::Utc::now();
        self.plans
            .iter()
            .filter(|p| {
                p.deadline
                    .map(|d| d < now && p.status != RemediationStatus::Completed)
                    .unwrap_or(false)
            })
            .collect()
    }

    pub fn completion_rate(&self) -> f64 {
        if self.plans.is_empty() {
            return 1.0;
        }
        let completed = self
            .plans
            .iter()
            .filter(|p| p.status == RemediationStatus::Completed)
            .count();
        completed as f64 / self.plans.len() as f64
    }
}

impl Default for RemediationTracker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_remediation_lifecycle() {
        let mut tracker = RemediationTracker::new();
        let plan = RemediationPlan {
            id: "plan-1".into(),
            gap_id: "gap-1".into(),
            control_id: "ctrl-1".into(),
            title: "Fix encryption".into(),
            description: "Implement encryption at rest".into(),
            steps: vec![
                RemediationStep {
                    order: 1,
                    description: "Select encryption algorithm".into(),
                    completed: false,
                    completed_at: None,
                },
                RemediationStep {
                    order: 2,
                    description: "Implement encryption".into(),
                    completed: false,
                    completed_at: None,
                },
            ],
            priority: RemediationPriority::High,
            owner: Some("admin".into()),
            deadline: None,
            status: RemediationStatus::NotStarted,
            created_at: chrono::Utc::now(),
        };

        tracker.create_plan(plan);
        tracker.update_step("plan-1", 1, true).unwrap();

        let plan = tracker.get_plan("plan-1").unwrap();
        assert_eq!(plan.status, RemediationStatus::InProgress);

        tracker.update_step("plan-1", 2, true).unwrap();
        let plan = tracker.get_plan("plan-1").unwrap();
        assert_eq!(plan.status, RemediationStatus::Completed);
    }
}
