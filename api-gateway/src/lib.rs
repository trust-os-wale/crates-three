//! API Gateway shared crate for Trust OS.
//!
//! Provides shared types, configuration, and middleware for the API gateway.

pub mod config;
pub mod proxy;
pub mod routing;

pub use config::*;
pub use proxy::*;
pub use routing::*;

use common::errors::{GrcError, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Backend service definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackendService {
    pub name: String,
    pub url: String,
    pub health_path: String,
    pub timeout_ms: u64,
    pub retry_count: u32,
}

/// API route definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiRoute {
    pub path: String,
    pub method: String,
    pub backend: String,
    pub auth_required: bool,
    pub rate_limit: Option<u32>,
    pub timeout_ms: Option<u64>,
}

/// Gateway configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayConfig {
    pub services: Vec<BackendService>,
    pub routes: Vec<ApiRoute>,
    pub cors_origins: Vec<String>,
    pub rate_limit_per_second: u32,
    pub jwt_secret: String,
    pub listen_addr: String,
}

impl GatewayConfig {
    pub fn from_env() -> Result<Self> {
        let jwt_secret = std::env::var("JWT_SECRET")
            .map_err(|_| GrcError::MissingConfiguration("JWT_SECRET".into()))?;

        if jwt_secret.len() < 32 {
            return Err(GrcError::InvalidConfiguration(
                "JWT_SECRET must be at least 32 characters".into(),
            ));
        }

        let listen_addr = std::env::var("LISTEN_ADDR").unwrap_or_else(|_| "127.0.0.1:8080".into());

        Ok(Self {
            services: Vec::new(),
            routes: Vec::new(),
            cors_origins: vec![
                std::env::var("CORS_ORIGIN").unwrap_or_else(|_| "http://localhost:3000".into())
            ],
            rate_limit_per_second: std::env::var("RATE_LIMIT")
                .unwrap_or_else(|_| "100".into())
                .parse()
                .unwrap_or(100),
            jwt_secret,
            listen_addr,
        })
    }
}

/// Rate limiter
pub struct RateLimiter {
    requests: HashMap<String, Vec<chrono::DateTime<chrono::Utc>>>,
    max_requests: u32,
    window_seconds: u64,
}

impl RateLimiter {
    pub fn new(max_requests: u32, window_seconds: u64) -> Self {
        Self {
            requests: HashMap::new(),
            max_requests,
            window_seconds,
        }
    }

    pub fn allow(&mut self, client_id: &str) -> bool {
        let now = chrono::Utc::now();
        let window_start = now - chrono::Duration::seconds(self.window_seconds as i64);

        let entries = self.requests.entry(client_id.to_string()).or_default();
        entries.retain(|t| *t > window_start);

        if entries.len() >= self.max_requests as usize {
            return false;
        }

        entries.push(now);
        true
    }

    pub fn remaining(&self, client_id: &str) -> u32 {
        let now = chrono::Utc::now();
        let window_start = now - chrono::Duration::seconds(self.window_seconds as i64);

        let count = self
            .requests
            .get(client_id)
            .map(|entries| entries.iter().filter(|t| **t > window_start).count() as u32)
            .unwrap_or(0);

        self.max_requests.saturating_sub(count)
    }
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new(100, 60)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rate_limiter() {
        let mut limiter = RateLimiter::new(3, 60);
        assert!(limiter.allow("client1"));
        assert!(limiter.allow("client1"));
        assert!(limiter.allow("client1"));
        assert!(!limiter.allow("client1"));
        assert_eq!(limiter.remaining("client1"), 0);
    }
}
