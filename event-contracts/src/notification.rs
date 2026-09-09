use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

pub const EVENT_NOTIFICATION_SENT: &str = "notification.sent";
pub const EVENT_NOTIFICATION_FAILED: &str = "notification.failed";
pub const EVENT_ALERT_TRIGGERED: &str = "alert.triggered";
pub const EVENT_ESCALATION_RAISED: &str = "escalation.raised";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationSent {
    pub tenant_id: String,
    pub notification_id: String,
    pub recipient: String,
    pub channel: String,
    pub notification_type: String,
    pub sent_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationFailed {
    pub tenant_id: String,
    pub notification_id: String,
    pub recipient: String,
    pub channel: String,
    pub error: String,
    pub failed_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertTriggered {
    pub tenant_id: String,
    pub alert_id: String,
    pub alert_type: String,
    pub severity: String,
    pub source: String,
    pub message: String,
    pub triggered_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EscalationRaised {
    pub tenant_id: String,
    pub escalation_id: String,
    pub alert_id: String,
    pub escalated_to: String,
    pub reason: String,
    pub raised_at: DateTime<Utc>,
}
