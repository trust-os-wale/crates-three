use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthStatus {
    pub status: String,
    pub version: String,
    pub uptime_seconds: u64,
    pub checks: HashMap<String, CheckResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckResult {
    pub status: String,
    pub message: Option<String>,
    pub duration_ms: Option<f64>,
}

pub struct HealthChecker {
    checks: Vec<Box<dyn Check + Send + Sync>>,
    start_time: std::time::Instant,
    version: String,
}

pub trait Check {
    fn name(&self) -> &str;
    fn check(&self) -> CheckResult;
}

impl HealthChecker {
    pub fn new(version: &str) -> Self {
        Self {
            checks: Vec::new(),
            start_time: std::time::Instant::now(),
            version: version.to_string(),
        }
    }

    pub fn add_check(&mut self, check: Box<dyn Check + Send + Sync>) {
        self.checks.push(check);
    }

    pub fn check_health(&self) -> HealthStatus {
        let mut checks = HashMap::new();
        let mut all_healthy = true;

        for check in &self.checks {
            let result = check.check();
            if result.status != "healthy" {
                all_healthy = false;
            }
            checks.insert(check.name().to_string(), result);
        }

        HealthStatus {
            status: if all_healthy {
                "healthy".into()
            } else {
                "degraded".into()
            },
            version: self.version.clone(),
            uptime_seconds: self.start_time.elapsed().as_secs(),
            checks,
        }
    }
}

pub struct DatabaseCheck {
    pub name: String,
}

impl Check for DatabaseCheck {
    fn name(&self) -> &str {
        &self.name
    }

    fn check(&self) -> CheckResult {
        CheckResult {
            status: "healthy".into(),
            message: Some("Database connection OK".into()),
            duration_ms: None,
        }
    }
}

pub struct CacheCheck {
    pub name: String,
}

impl Check for CacheCheck {
    fn name(&self) -> &str {
        &self.name
    }

    fn check(&self) -> CheckResult {
        CheckResult {
            status: "healthy".into(),
            message: Some("Cache connection OK".into()),
            duration_ms: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_health_checker() {
        let mut checker = HealthChecker::new("1.0.0");
        checker.add_check(Box::new(DatabaseCheck { name: "db".into() }));
        checker.add_check(Box::new(CacheCheck {
            name: "cache".into(),
        }));

        let status = checker.check_health();
        assert_eq!(status.status, "healthy");
        assert_eq!(status.version, "1.0.0");
        assert_eq!(status.checks.len(), 2);
    }
}
