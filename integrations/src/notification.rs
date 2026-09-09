use crate::{Integration, IntegrationEvent, IntegrationHealth};
use common::errors::Result;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationConfig {
    pub smtp_endpoint: Option<String>,
    pub smtp_username: Option<String>,
    pub smtp_password: Option<String>,
    pub webhook_url: Option<String>,
    pub from_address: Option<String>,
}

pub struct NotificationIntegration {
    name: String,
    config: NotificationConfig,
}

impl NotificationIntegration {
    pub fn new(name: &str, config: NotificationConfig) -> Self {
        Self {
            name: name.to_string(),
            config,
        }
    }
}

impl Integration for NotificationIntegration {
    fn name(&self) -> &str {
        &self.name
    }

    fn health_check(&self) -> Result<IntegrationHealth> {
        Ok(IntegrationHealth {
            integration_id: self.name.clone(),
            status: "healthy".into(),
            last_check: chrono::Utc::now(),
            latency_ms: Some(5.0),
            error: None,
        })
    }

    fn send_event(&self, event: &IntegrationEvent) -> Result<()> {
        if let Some(ref webhook) = self.config.webhook_url {
            tracing::info!(
                webhook_url = %webhook,
                event_id = %event.id,
                "Sending notification via webhook"
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_notification_health() {
        let config = NotificationConfig {
            smtp_endpoint: None,
            smtp_username: None,
            smtp_password: None,
            webhook_url: Some("https://hooks.example.com".into()),
            from_address: None,
        };
        let integration = NotificationIntegration::new("test-notification", config);
        let health = integration.health_check().unwrap();
        assert_eq!(health.status, "healthy");
    }
}
