use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

pub const EVENT_REPORT_GENERATED: &str = "report.generated";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportGenerated {
    pub tenant_id: String,
    pub report_id: String,
    pub report_type: String,
    pub format: String,
    pub generated_by: String,
    pub generated_at: DateTime<Utc>,
}
