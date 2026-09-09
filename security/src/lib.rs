// Security module for Trust OS - Rate limiting, mTLS, Secret management

use chrono::{DateTime, Duration, Utc};
use common::{
    errors::{GrcError, Result},
    traits::CacheProvider,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;

// ============================================
// RATE LIMITER
// ============================================

#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    pub max_requests: u32,
    pub window_seconds: u64,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            max_requests: 1000,
            window_seconds: 60,
        }
    }
}

pub struct RateLimiter {
    cache: Arc<dyn CacheProvider>,
    config: RateLimitConfig,
}

impl RateLimiter {
    pub fn new(cache: Arc<dyn CacheProvider>, config: RateLimitConfig) -> Self {
        Self { cache, config }
    }

    /// Check if a request should be allowed
    pub async fn check_limit(&self, key: &str) -> Result<bool> {
        let key = format!("rate_limit:{}", key);

        let count = self.cache.increment(&key).await.unwrap_or(0);

        if count == 1 {
            // First request in this window, set TTL
            self.cache
                .set(&key, "1".into(), self.config.window_seconds)
                .await?;
        }

        Ok(count <= self.config.max_requests as i64)
    }

    /// Get current request count for a key
    pub async fn get_count(&self, key: &str) -> Result<i64> {
        let key = format!("rate_limit:{}", key);
        let count_str = self.cache.get(&key).await?;

        Ok(count_str.and_then(|s| s.parse::<i64>().ok()).unwrap_or(0))
    }

    /// Reset rate limit for a key
    pub async fn reset(&self, key: &str) -> Result<()> {
        let key = format!("rate_limit:{}", key);
        self.cache.delete(&key).await
    }
}

// ============================================
// SECRET MANAGER
// ============================================

#[derive(Debug, Clone)]
pub struct Secret {
    pub name: String,
    pub value: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub rotation_enabled: bool,
    pub rotation_days: u32,
}

pub struct SecretsManager {
    cache: Arc<dyn CacheProvider>,
    // In production, this would connect to HashiCorp Vault or AWS Secrets Manager
    secrets_store: Arc<tokio::sync::RwLock<HashMap<String, Secret>>>,
}

impl SecretsManager {
    pub fn new(cache: Arc<dyn CacheProvider>) -> Self {
        Self {
            cache,
            secrets_store: Arc::new(tokio::sync::RwLock::new(HashMap::new())),
        }
    }

    /// Store a secret
    pub async fn store_secret(&self, name: String, value: String) -> Result<()> {
        let secret = Secret {
            name: name.clone(),
            value: value.clone(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            rotation_enabled: false,
            rotation_days: 90,
        };

        // Store in cache for performance
        self.cache
            .set(&format!("secret:{}", name), value, 3600)
            .await?;

        // Store in persistent store
        let mut store = self.secrets_store.write().await;
        store.insert(name, secret);

        Ok(())
    }

    /// Retrieve a secret
    pub async fn get_secret(&self, name: &str) -> Result<String> {
        // Try cache first
        if let Ok(Some(value)) = self.cache.get(&format!("secret:{}", name)).await {
            return Ok(value);
        }

        // Fall back to persistent store
        let store = self.secrets_store.read().await;
        store
            .get(name)
            .map(|s| s.value.clone())
            .ok_or_else(|| GrcError::InternalError(format!("Secret not found: {}", name)))
    }

    /// Rotate a secret
    pub async fn rotate_secret(&self, name: &str, new_value: String) -> Result<()> {
        self.store_secret(name.into(), new_value).await
    }

    /// Delete a secret
    pub async fn delete_secret(&self, name: &str) -> Result<()> {
        self.cache.delete(&format!("secret:{}", name)).await?;

        let mut store = self.secrets_store.write().await;
        store.remove(name);

        Ok(())
    }

    /// Enable automatic rotation for a secret
    pub async fn enable_rotation(&self, name: &str, rotation_days: u32) -> Result<()> {
        let mut store = self.secrets_store.write().await;

        if let Some(secret) = store.get_mut(name) {
            secret.rotation_enabled = true;
            secret.rotation_days = rotation_days;
            Ok(())
        } else {
            Err(GrcError::InternalError(format!(
                "Secret not found: {}",
                name
            )))
        }
    }
}

// ============================================
// MTLS CERTIFICATE MANAGER
// ============================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Certificate {
    pub name: String,
    pub cert_pem: String,
    pub key_pem: String,
    pub issuer: String,
    pub subject: String,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub fingerprint: String,
}

impl Certificate {
    /// Check if certificate is expired
    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at
    }

    /// Check if certificate is expiring soon (within 30 days)
    pub fn is_expiring_soon(&self) -> bool {
        let expiration_warning = Utc::now() + Duration::days(30);
        self.expires_at < expiration_warning && !self.is_expired()
    }
}

pub struct CertificateManager {
    cache: Arc<dyn CacheProvider>,
    certs: Arc<tokio::sync::RwLock<HashMap<String, Certificate>>>,
}

impl CertificateManager {
    pub fn new(cache: Arc<dyn CacheProvider>) -> Self {
        Self {
            cache,
            certs: Arc::new(tokio::sync::RwLock::new(HashMap::new())),
        }
    }

    /// Store a certificate
    pub async fn store_certificate(&self, cert: Certificate) -> Result<()> {
        if cert.is_expired() {
            return Err(GrcError::InternalError(
                "Cannot store expired certificate".into(),
            ));
        }

        // Cache the certificate
        let cert_str = serde_json::to_string(&cert)
            .map_err(|e| GrcError::InternalError(format!("Serialization failed: {}", e)))?;

        self.cache
            .set(&format!("cert:{}", cert.name), cert_str, 86400)
            .await?;

        // Store in persistent store
        let mut certs = self.certs.write().await;
        certs.insert(cert.name.clone(), cert);

        Ok(())
    }

    /// Retrieve a certificate
    pub async fn get_certificate(&self, name: &str) -> Result<Certificate> {
        let certs = self.certs.read().await;
        certs
            .get(name)
            .cloned()
            .ok_or_else(|| GrcError::InternalError(format!("Certificate not found: {}", name)))
    }

    /// Get certificates expiring soon
    pub async fn get_expiring_certificates(&self, days: u32) -> Result<Vec<Certificate>> {
        let certs = self.certs.read().await;
        let expiration_warning = Utc::now() + Duration::days(days as i64);

        let expiring: Vec<_> = certs
            .values()
            .filter(|cert| {
                !cert.is_expired()
                    && cert.expires_at < expiration_warning
                    && cert.is_expiring_soon()
            })
            .cloned()
            .collect();

        Ok(expiring)
    }
}

// ============================================
// CRYPTOGRAPHY UTILITIES
// ============================================

pub struct CryptoUtils;

impl CryptoUtils {
    /// Generate a random key of specified length
    pub fn generate_random_key(length: usize) -> Vec<u8> {
        use rand::RngCore;

        let mut key = vec![0u8; length];
        let mut rng = rand::thread_rng();
        rng.fill_bytes(&mut key);
        key
    }

    /// Compute SHA256 hash
    pub fn sha256(data: &[u8]) -> Vec<u8> {
        use sha2::{Digest, Sha256};

        let mut hasher = Sha256::new();
        hasher.update(data);
        hasher.finalize().to_vec()
    }

    /// Compute HMAC-SHA256
    pub fn hmac_sha256(key: &[u8], data: &[u8]) -> std::result::Result<Vec<u8>, String> {
        use hmac::{Hmac, Mac};

        type HmacSha256 = Hmac<sha2::Sha256>;

        let mut mac =
            HmacSha256::new_from_slice(key).map_err(|e| format!("HMAC key error: {}", e))?;
        mac.update(data);
        Ok(mac.finalize().into_bytes().to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rate_limit_config_default() {
        let config = RateLimitConfig::default();
        assert_eq!(config.max_requests, 1000);
        assert_eq!(config.window_seconds, 60);
    }

    #[test]
    fn test_certificate_expiration() {
        let cert = Certificate {
            name: "test".into(),
            cert_pem: "".into(),
            key_pem: "".into(),
            issuer: "CA".into(),
            subject: "test.com".into(),
            issued_at: Utc::now(),
            expires_at: Utc::now() - Duration::days(1),
            fingerprint: "abc123".into(),
        };

        assert!(cert.is_expired());
    }

    #[test]
    fn test_certificate_expiring_soon() {
        let cert = Certificate {
            name: "test".into(),
            cert_pem: "".into(),
            key_pem: "".into(),
            issuer: "CA".into(),
            subject: "test.com".into(),
            issued_at: Utc::now(),
            expires_at: Utc::now() + Duration::days(20),
            fingerprint: "abc123".into(),
        };

        assert!(cert.is_expiring_soon());
        assert!(!cert.is_expired());
    }

    #[test]
    fn test_crypto_utils_random_key() {
        let key1 = CryptoUtils::generate_random_key(32);
        let key2 = CryptoUtils::generate_random_key(32);

        assert_eq!(key1.len(), 32);
        assert_eq!(key2.len(), 32);
        assert_ne!(key1, key2);
    }

    #[test]
    fn test_sha256_hash() {
        let data = b"test data";
        let hash = CryptoUtils::sha256(data);

        assert_eq!(hash.len(), 32); // SHA256 produces 32 bytes
    }
}
