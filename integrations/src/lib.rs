//! Integrations crate for Trust OS.
//!
//! Provides external service integration adapters for SIEM,
//! ticketing, ITSM, cloud providers, and notification services.

pub mod notification;
pub mod siem;
pub mod ticketing;

pub use notification::*;
pub use siem::*;
pub use ticketing::*;

use common::errors::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Integration configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrationConfig {
    pub id: String,
    pub name: String,
    pub integration_type: IntegrationType,
    pub endpoint: String,
    pub credentials: HashMap<String, String>,
    pub enabled: bool,
    pub metadata: HashMap<String, String>,
}

/// Types of integrations
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum IntegrationType {
    Siem,
    Ticketing,
    Itsm,
    Notification,
    CloudProvider,
    Webhook,
    Custom,
}

/// Integration health status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrationHealth {
    pub integration_id: String,
    pub status: String,
    pub last_check: chrono::DateTime<chrono::Utc>,
    pub latency_ms: Option<f64>,
    pub error: Option<String>,
}

/// Base trait for all integrations
pub trait Integration: Send + Sync {
    fn name(&self) -> &str;
    fn health_check(&self) -> Result<IntegrationHealth>;
    fn send_event(&self, event: &IntegrationEvent) -> Result<()>;
}

/// Event to send to external systems
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrationEvent {
    pub id: String,
    pub source: String,
    pub event_type: String,
    pub severity: String,
    pub title: String,
    pub description: String,
    pub details: HashMap<String, String>,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

impl IntegrationEvent {
    pub fn new(source: &str, event_type: &str, title: &str) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            source: source.to_string(),
            event_type: event_type.to_string(),
            severity: "info".into(),
            title: title.to_string(),
            description: String::new(),
            details: HashMap::new(),
            timestamp: chrono::Utc::now(),
        }
    }
}

/// Integration manager — manages multiple integrations
pub struct IntegrationManager {
    integrations: HashMap<String, Box<dyn Integration>>,
}

impl IntegrationManager {
    pub fn new() -> Self {
        Self {
            integrations: HashMap::new(),
        }
    }

    pub fn register(&mut self, integration: Box<dyn Integration>) {
        let name = integration.name().to_string();
        self.integrations.insert(name, integration);
    }

    pub fn send_event(&self, event: &IntegrationEvent) -> Result<()> {
        for integration in self.integrations.values() {
            if let Err(e) = integration.send_event(event) {
                tracing::warn!("Integration '{}' failed: {}", integration.name(), e);
            }
        }
        Ok(())
    }

    pub fn health_check_all(&self) -> Vec<IntegrationHealth> {
        self.integrations
            .values()
            .filter_map(|i| i.health_check().ok())
            .collect()
    }
}

impl Default for IntegrationManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_integration_event() {
        let event = IntegrationEvent::new("trust-os", "alert", "Security Alert");
        assert_eq!(event.source, "trust-os");
        assert_eq!(event.event_type, "alert");
    }
}
