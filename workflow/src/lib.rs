//! Workflow crate for Trust OS.
//!
//! Provides workflow definition, execution, and state management
//! for governance, compliance, and risk workflows.

use common::errors::{GrcError, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

/// Workflow unique identifier
pub type WorkflowId = String;

/// Step unique identifier
pub type StepId = String;

/// Workflow definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowDefinition {
    pub id: WorkflowId,
    pub name: String,
    pub description: String,
    pub version: u32,
    pub steps: Vec<WorkflowStep>,
    pub transitions: Vec<WorkflowTransition>,
    pub metadata: HashMap<String, String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

/// A single step in a workflow
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowStep {
    pub id: StepId,
    pub name: String,
    pub step_type: StepType,
    pub required: bool,
    pub timeout_seconds: Option<u64>,
    pub retry_policy: Option<RetryPolicy>,
    pub metadata: HashMap<String, String>,
}

/// Types of workflow steps
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum StepType {
    Approval,
    Review,
    Execution,
    Notification,
    Validation,
    Gate,
    Parallel,
    Conditional,
}

/// Retry policy for failed steps
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetryPolicy {
    pub max_retries: u32,
    pub backoff_seconds: u64,
    pub backoff_multiplier: f64,
}

/// Transition between workflow steps
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowTransition {
    pub from_step: StepId,
    pub to_step: StepId,
    pub condition: Option<String>,
    pub transition_type: TransitionType,
}

/// Types of transitions
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum TransitionType {
    Auto,
    OnApproval,
    OnRejection,
    OnTimeout,
    OnCondition,
}

/// Active workflow instance
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowInstance {
    pub id: String,
    pub definition_id: WorkflowId,
    pub tenant_id: String,
    pub status: WorkflowStatus,
    pub current_step: Option<StepId>,
    pub step_states: HashMap<StepId, StepState>,
    pub context: HashMap<String, String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
    pub completed_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// Workflow instance status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum WorkflowStatus {
    Pending,
    Running,
    Paused,
    Completed,
    Failed,
    Cancelled,
}

/// State of a single step
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StepState {
    pub step_id: StepId,
    pub status: StepStatus,
    pub assignee: Option<String>,
    pub started_at: Option<chrono::DateTime<chrono::Utc>>,
    pub completed_at: Option<chrono::DateTime<chrono::Utc>>,
    pub result: Option<String>,
    pub error: Option<String>,
    pub retries: u32,
}

/// Step execution status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum StepStatus {
    Pending,
    InProgress,
    Completed,
    Failed,
    Skipped,
    TimedOut,
}

/// Workflow engine — manages workflow execution
pub struct WorkflowEngine {
    definitions: HashMap<WorkflowId, WorkflowDefinition>,
    instances: HashMap<String, WorkflowInstance>,
}

impl WorkflowEngine {
    pub fn new() -> Self {
        Self {
            definitions: HashMap::new(),
            instances: HashMap::new(),
        }
    }

    /// Register a workflow definition
    pub fn register_definition(&mut self, definition: WorkflowDefinition) -> Result<()> {
        self.definitions.insert(definition.id.clone(), definition);
        Ok(())
    }

    /// Start a new workflow instance
    pub fn start_workflow(
        &mut self,
        definition_id: &WorkflowId,
        tenant_id: &str,
        context: HashMap<String, String>,
    ) -> Result<WorkflowInstance> {
        let definition = self
            .definitions
            .get(definition_id)
            .ok_or_else(|| GrcError::WorkflowNotFound(definition_id.clone()))?;

        let first_step = definition.steps.first().map(|s| s.id.clone());

        let mut step_states = HashMap::new();
        for step in &definition.steps {
            step_states.insert(
                step.id.clone(),
                StepState {
                    step_id: step.id.clone(),
                    status: if Some(step.id.clone()) == first_step {
                        StepStatus::InProgress
                    } else {
                        StepStatus::Pending
                    },
                    assignee: None,
                    started_at: if Some(step.id.clone()) == first_step {
                        Some(chrono::Utc::now())
                    } else {
                        None
                    },
                    completed_at: None,
                    result: None,
                    error: None,
                    retries: 0,
                },
            );
        }

        let instance = WorkflowInstance {
            id: Uuid::new_v4().to_string(),
            definition_id: definition_id.clone(),
            tenant_id: tenant_id.to_string(),
            status: WorkflowStatus::Running,
            current_step: first_step,
            step_states,
            context,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            completed_at: None,
        };

        self.instances.insert(instance.id.clone(), instance.clone());
        Ok(instance)
    }

    /// Complete a step in a workflow
    pub fn complete_step(
        &mut self,
        instance_id: &str,
        step_id: &StepId,
        result: Option<String>,
    ) -> Result<()> {
        let instance = self
            .instances
            .get_mut(instance_id)
            .ok_or_else(|| GrcError::WorkflowNotFound(instance_id.to_string()))?;

        let step_state = instance
            .step_states
            .get_mut(step_id)
            .ok_or_else(|| GrcError::InvalidWorkflowState(format!("Step {} not found", step_id)))?;

        step_state.status = StepStatus::Completed;
        step_state.completed_at = Some(chrono::Utc::now());
        step_state.result = result;

        // Find next step
        let definition = self
            .definitions
            .get(&instance.definition_id)
            .ok_or_else(|| GrcError::WorkflowNotFound(instance.definition_id.clone()))?;

        let next_transition = definition
            .transitions
            .iter()
            .find(|t| t.from_step == *step_id && t.transition_type == TransitionType::Auto);

        if let Some(transition) = next_transition {
            instance.current_step = Some(transition.to_step.clone());
            if let Some(next_state) = instance.step_states.get_mut(&transition.to_step) {
                next_state.status = StepStatus::InProgress;
                next_state.started_at = Some(chrono::Utc::now());
            }
        } else {
            // Check if all steps are complete
            let all_complete = instance
                .step_states
                .values()
                .all(|s| s.status == StepStatus::Completed || s.status == StepStatus::Skipped);

            if all_complete {
                instance.status = WorkflowStatus::Completed;
                instance.completed_at = Some(chrono::Utc::now());
                instance.current_step = None;
            }
        }

        instance.updated_at = chrono::Utc::now();
        Ok(())
    }

    /// Get a workflow instance
    pub fn get_instance(&self, instance_id: &str) -> Result<WorkflowInstance> {
        self.instances
            .get(instance_id)
            .cloned()
            .ok_or_else(|| GrcError::WorkflowNotFound(instance_id.to_string()))
    }

    /// List all instances for a tenant
    pub fn list_instances(&self, tenant_id: &str) -> Vec<WorkflowInstance> {
        self.instances
            .values()
            .filter(|i| i.tenant_id == tenant_id)
            .cloned()
            .collect()
    }
}

impl Default for WorkflowEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_definition() -> WorkflowDefinition {
        WorkflowDefinition {
            id: "wf-test".into(),
            name: "Test Workflow".into(),
            description: "A test workflow".into(),
            version: 1,
            steps: vec![
                WorkflowStep {
                    id: "step-1".into(),
                    name: "Submit".into(),
                    step_type: StepType::Execution,
                    required: true,
                    timeout_seconds: None,
                    retry_policy: None,
                    metadata: HashMap::new(),
                },
                WorkflowStep {
                    id: "step-2".into(),
                    name: "Approve".into(),
                    step_type: StepType::Approval,
                    required: true,
                    timeout_seconds: Some(86400),
                    retry_policy: None,
                    metadata: HashMap::new(),
                },
                WorkflowStep {
                    id: "step-3".into(),
                    name: "Execute".into(),
                    step_type: StepType::Execution,
                    required: true,
                    timeout_seconds: None,
                    retry_policy: None,
                    metadata: HashMap::new(),
                },
            ],
            transitions: vec![
                WorkflowTransition {
                    from_step: "step-1".into(),
                    to_step: "step-2".into(),
                    condition: None,
                    transition_type: TransitionType::Auto,
                },
                WorkflowTransition {
                    from_step: "step-2".into(),
                    to_step: "step-3".into(),
                    condition: None,
                    transition_type: TransitionType::Auto,
                },
            ],
            metadata: HashMap::new(),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        }
    }

    #[test]
    fn test_workflow_lifecycle() {
        let mut engine = WorkflowEngine::new();
        engine.register_definition(test_definition()).unwrap();

        let instance = engine
            .start_workflow(&"wf-test".into(), "tenant-1", HashMap::new())
            .unwrap();

        assert_eq!(instance.status, WorkflowStatus::Running);
        assert_eq!(instance.current_step, Some("step-1".into()));

        engine
            .complete_step(&instance.id, &"step-1".into(), None)
            .unwrap();
        let instance = engine.get_instance(&instance.id).unwrap();
        assert_eq!(instance.current_step, Some("step-2".into()));

        engine
            .complete_step(&instance.id, &"step-2".into(), Some("approved".into()))
            .unwrap();
        let instance = engine.get_instance(&instance.id).unwrap();
        assert_eq!(instance.current_step, Some("step-3".into()));

        engine
            .complete_step(&instance.id, &"step-3".into(), None)
            .unwrap();
        let instance = engine.get_instance(&instance.id).unwrap();
        assert_eq!(instance.status, WorkflowStatus::Completed);
    }

    #[test]
    fn test_workflow_not_found() {
        let engine = WorkflowEngine::new();
        let result = engine.get_instance("nonexistent");
        assert!(result.is_err());
    }

    #[test]
    fn test_workflow_step_not_found() {
        let mut engine = WorkflowEngine::new();
        engine.register_definition(test_definition()).unwrap();

        let instance = engine
            .start_workflow(&"wf-test".into(), "tenant-1", HashMap::new())
            .unwrap();

        let result = engine.complete_step(&instance.id, &"nonexistent".into(), None);
        assert!(result.is_err());
    }
}
