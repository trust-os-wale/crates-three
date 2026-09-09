use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthStatus {
    pub service: String,
    pub status: HealthState,
    pub version: String,
    pub timestamp: String,
    pub checks: HashMap<String, ComponentHealth>,
    pub uptime_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum HealthState {
    Healthy,
    Degraded,
    Unhealthy,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComponentHealth {
    pub name: String,
    pub status: HealthState,
    pub latency_ms: u64,
    pub error: Option<String>,
    pub last_check: String,
}

pub struct HealthRegistry {
    service_name: String,
    version: String,
    start_time: chrono::DateTime<Utc>,
    checks: Arc<RwLock<HashMap<String, Arc<dyn HealthCheck + Send + Sync>>>>,
}

#[async_trait::async_trait]
pub trait HealthCheck {
    async fn check(&self) -> ComponentHealth;
}

impl HealthRegistry {
    pub fn new(service_name: String, version: String) -> Self {
        Self {
            service_name,
            version,
            start_time: Utc::now(),
            checks: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn register(&self, name: String, check: Arc<dyn HealthCheck + Send + Sync>) {
        let mut checks = self.checks.write().await;
        checks.insert(name, check);
    }

    pub async fn status(&self) -> HealthStatus {
        let mut checks = HashMap::new();
        let mut overall = HealthState::Healthy;

        let registry = self.checks.read().await;
        for (name, check) in registry.iter() {
            let component = check.check().await;
            if component.status == HealthState::Unhealthy {
                overall = HealthState::Unhealthy;
            } else if component.status == HealthState::Degraded && overall != HealthState::Unhealthy
            {
                overall = HealthState::Degraded;
            }
            checks.insert(name.clone(), component);
        }

        let uptime = (Utc::now() - self.start_time).num_seconds() as u64;

        HealthStatus {
            service: self.service_name.clone(),
            status: overall,
            version: self.version.clone(),
            timestamp: Utc::now().to_rfc3339(),
            checks,
            uptime_seconds: uptime,
        }
    }
}
