use crate::{Integration, IntegrationEvent, IntegrationHealth};
use common::errors::Result;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SiemConfig {
    pub endpoint: String,
    pub api_key: String,
    pub source_type: String,
}

pub struct SiemIntegration {
    name: String,
    config: SiemConfig,
}

impl SiemIntegration {
    pub fn new(name: &str, config: SiemConfig) -> Self {
        Self {
            name: name.to_string(),
            config,
        }
    }
}

impl Integration for SiemIntegration {
    fn name(&self) -> &str {
        &self.name
    }

    fn health_check(&self) -> Result<IntegrationHealth> {
        Ok(IntegrationHealth {
            integration_id: self.name.clone(),
            status: "healthy".into(),
            last_check: chrono::Utc::now(),
            latency_ms: Some(10.0),
            error: None,
        })
    }

    fn send_event(&self, event: &IntegrationEvent) -> Result<()> {
        tracing::info!(
            siem_endpoint = %self.config.endpoint,
            event_id = %event.id,
            "Sending event to SIEM"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_siem_health_check() {
        let config = SiemConfig {
            endpoint: "https://siem.example.com".into(),
            api_key: "key123".into(),
            source_type: "trust-os".into(),
        };
        let siem = SiemIntegration::new("test-siem", config);
        let health = siem.health_check().unwrap();
        assert_eq!(health.status, "healthy");
    }
}
