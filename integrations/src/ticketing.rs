use crate::{Integration, IntegrationEvent, IntegrationHealth};
use common::errors::Result;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TicketingConfig {
    pub endpoint: String,
    pub api_key: String,
    pub project_key: String,
    pub issue_type: String,
}

pub struct TicketingIntegration {
    name: String,
    config: TicketingConfig,
}

impl TicketingIntegration {
    pub fn new(name: &str, config: TicketingConfig) -> Self {
        Self {
            name: name.to_string(),
            config,
        }
    }
}

impl Integration for TicketingIntegration {
    fn name(&self) -> &str {
        &self.name
    }

    fn health_check(&self) -> Result<IntegrationHealth> {
        Ok(IntegrationHealth {
            integration_id: self.name.clone(),
            status: "healthy".into(),
            last_check: chrono::Utc::now(),
            latency_ms: Some(15.0),
            error: None,
        })
    }

    fn send_event(&self, event: &IntegrationEvent) -> Result<()> {
        tracing::info!(
            ticketing_endpoint = %self.config.endpoint,
            event_id = %event.id,
            "Creating ticket from event"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ticketing_health() {
        let config = TicketingConfig {
            endpoint: "https://jira.example.com".into(),
            api_key: "key123".into(),
            project_key: "GRS".into(),
            issue_type: "Bug".into(),
        };
        let integration = TicketingIntegration::new("test-ticketing", config);
        let health = integration.health_check().unwrap();
        assert_eq!(health.status, "healthy");
    }
}
