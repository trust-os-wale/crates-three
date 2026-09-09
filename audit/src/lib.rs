//! Audit trail crate for Trust OS.
//!
//! Provides immutable audit event storage, integrity verification,
//! and compliance audit trail capabilities.

pub mod events;
pub mod store;
pub mod verification;

pub use events::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
pub use store::*;
pub use verification::*;

/// Audit event categories
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum AuditCategory {
    Authentication,
    Authorization,
    DataAccess,
    DataModification,
    ConfigurationChange,
    ComplianceAction,
    RiskAssessment,
    PolicyChange,
    SystemEvent,
    SecurityEvent,
}

/// Audit event severity
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum AuditSeverity {
    Info,
    Warning,
    Error,
    Critical,
}

/// An immutable audit event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub id: String,
    pub tenant_id: String,
    pub category: AuditCategory,
    pub severity: AuditSeverity,
    pub actor: String,
    pub action: String,
    pub resource_type: String,
    pub resource_id: String,
    pub details: HashMap<String, String>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub signature: Option<String>,
}

/// Audit event query filter
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditQuery {
    pub tenant_id: Option<String>,
    pub category: Option<AuditCategory>,
    pub severity: Option<AuditSeverity>,
    pub actor: Option<String>,
    pub resource_type: Option<String>,
    pub start_time: Option<chrono::DateTime<chrono::Utc>>,
    pub end_time: Option<chrono::DateTime<chrono::Utc>>,
    pub limit: Option<usize>,
    pub offset: Option<usize>,
}

/// Audit trail query result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditTrail {
    pub events: Vec<AuditEvent>,
    pub total_count: usize,
    pub has_more: bool,
}

impl AuditEvent {
    pub fn new(
        tenant_id: &str,
        category: AuditCategory,
        severity: AuditSeverity,
        actor: &str,
        action: &str,
        resource_type: &str,
        resource_id: &str,
    ) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            tenant_id: tenant_id.to_string(),
            category,
            severity,
            actor: actor.to_string(),
            action: action.to_string(),
            resource_type: resource_type.to_string(),
            resource_id: resource_id.to_string(),
            details: HashMap::new(),
            ip_address: None,
            user_agent: None,
            timestamp: chrono::Utc::now(),
            signature: None,
        }
    }

    pub fn with_detail(mut self, key: &str, value: &str) -> Self {
        self.details.insert(key.to_string(), value.to_string());
        self
    }

    pub fn with_ip(mut self, ip: &str) -> Self {
        self.ip_address = Some(ip.to_string());
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audit_event_creation() {
        let event = AuditEvent::new(
            "tenant-1",
            AuditCategory::Authentication,
            AuditSeverity::Info,
            "user-1",
            "login",
            "session",
            "sess-123",
        );

        assert_eq!(event.tenant_id, "tenant-1");
        assert_eq!(event.category, AuditCategory::Authentication);
        assert_eq!(event.actor, "user-1");
    }

    #[test]
    fn test_audit_event_with_details() {
        let event = AuditEvent::new(
            "tenant-1",
            AuditCategory::DataAccess,
            AuditSeverity::Info,
            "user-1",
            "read",
            "document",
            "doc-123",
        )
        .with_detail("field", "name")
        .with_ip("192.168.1.1");

        assert_eq!(event.details.get("field").unwrap(), "name");
        assert_eq!(event.ip_address.unwrap(), "192.168.1.1");
    }
}
