use crate::{AuditCategory, AuditEvent, AuditSeverity};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEventBatch {
    pub events: Vec<AuditEvent>,
    pub batch_id: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

impl AuditEventBatch {
    pub fn new(events: Vec<AuditEvent>) -> Self {
        Self {
            events,
            batch_id: uuid::Uuid::new_v4().to_string(),
            created_at: chrono::Utc::now(),
        }
    }

    pub fn size(&self) -> usize {
        self.events.len()
    }

    pub fn filter_by_category(&self, category: &AuditCategory) -> Vec<&AuditEvent> {
        self.events
            .iter()
            .filter(|e| &e.category == category)
            .collect()
    }

    pub fn filter_by_severity(&self, severity: &AuditSeverity) -> Vec<&AuditEvent> {
        self.events
            .iter()
            .filter(|e| &e.severity == severity)
            .collect()
    }

    pub fn critical_events(&self) -> Vec<&AuditEvent> {
        self.filter_by_severity(&AuditSeverity::Critical)
    }
}

pub struct AuditEventFactory;

impl AuditEventFactory {
    pub fn authentication_event(
        tenant_id: &str,
        actor: &str,
        action: &str,
        success: bool,
    ) -> AuditEvent {
        let severity = if success {
            AuditSeverity::Info
        } else {
            AuditSeverity::Warning
        };
        AuditEvent::new(
            tenant_id,
            AuditCategory::Authentication,
            severity,
            actor,
            action,
            "session",
            &uuid::Uuid::new_v4().to_string(),
        )
        .with_detail("success", &success.to_string())
    }

    pub fn data_access_event(
        tenant_id: &str,
        actor: &str,
        resource_type: &str,
        resource_id: &str,
    ) -> AuditEvent {
        AuditEvent::new(
            tenant_id,
            AuditCategory::DataAccess,
            AuditSeverity::Info,
            actor,
            "access",
            resource_type,
            resource_id,
        )
    }

    pub fn data_modification_event(
        tenant_id: &str,
        actor: &str,
        resource_type: &str,
        resource_id: &str,
        operation: &str,
    ) -> AuditEvent {
        AuditEvent::new(
            tenant_id,
            AuditCategory::DataModification,
            AuditSeverity::Info,
            actor,
            operation,
            resource_type,
            resource_id,
        )
        .with_detail("operation", operation)
    }

    pub fn security_event(tenant_id: &str, actor: &str, action: &str, details: &str) -> AuditEvent {
        AuditEvent::new(
            tenant_id,
            AuditCategory::SecurityEvent,
            AuditSeverity::Critical,
            actor,
            action,
            "security",
            &uuid::Uuid::new_v4().to_string(),
        )
        .with_detail("details", details)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_batch() {
        let events = vec![
            AuditEventFactory::authentication_event("t1", "user1", "login", true),
            AuditEventFactory::data_access_event("t1", "user1", "doc", "d1"),
        ];
        let batch = AuditEventBatch::new(events);
        assert_eq!(batch.size(), 2);
        assert!(!batch.batch_id.is_empty());
    }

    #[test]
    fn test_factory_methods() {
        let event = AuditEventFactory::security_event("t1", "user1", "breach_detected", "details");
        assert_eq!(event.category, AuditCategory::SecurityEvent);
        assert_eq!(event.severity, AuditSeverity::Critical);
    }
}
