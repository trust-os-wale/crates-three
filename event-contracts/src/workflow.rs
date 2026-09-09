use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

pub const EVENT_WORKFLOW_STARTED: &str = "workflow.started";
pub const EVENT_WORKFLOW_COMPLETED: &str = "workflow.completed";
pub const EVENT_WORKFLOW_FAILED: &str = "workflow.failed";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowStarted {
    pub tenant_id: String,
    pub workflow_id: String,
    pub workflow_type: String,
    pub triggered_by: String,
    pub input_params: std::collections::HashMap<String, String>,
    pub started_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowCompleted {
    pub tenant_id: String,
    pub workflow_id: String,
    pub workflow_type: String,
    pub result: String,
    pub completed_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowFailed {
    pub tenant_id: String,
    pub workflow_id: String,
    pub workflow_type: String,
    pub error: String,
    pub failed_at: DateTime<Utc>,
}
