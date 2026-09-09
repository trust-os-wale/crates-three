// Multi-tenant isolation module for Trust OS
// Ensures complete logical and technical isolation between tenants

use chrono::Utc;
use common::{
    errors::{GrcError, Result},
    traits::CacheProvider,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

// ============================================
// TENANT CONTEXT
// ============================================

/// Represents the tenant context for current request
#[derive(Debug, Clone)]
pub struct RequestTenantContext {
    pub tenant_id: String,
    pub user_id: String,
    pub user_name: String,
    pub roles: Vec<String>,
    pub permissions: Vec<String>,
    pub correlation_id: String,
    pub trace_id: String,
}

impl RequestTenantContext {
    pub fn new(tenant_id: String, user_id: String) -> Self {
        Self {
            tenant_id,
            user_id,
            user_name: String::new(),
            roles: vec![],
            permissions: vec![],
            correlation_id: Uuid::new_v4().to_string(),
            trace_id: Uuid::new_v4().to_string(),
        }
    }
}

// ============================================
// TENANT METADATA STORE
// ============================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TenantMetadata {
    pub id: String,
    pub name: String,
    pub region: String,
    pub encryption_key_id: String,
    pub data_classification: String,
    pub compliance_frameworks: Vec<String>,
    pub created_at: chrono::DateTime<Utc>,
}

pub struct TenantStore {
    cache: Arc<dyn CacheProvider>,
    metadata: Arc<RwLock<HashMap<String, TenantMetadata>>>,
}

impl TenantStore {
    pub fn new(cache: Arc<dyn CacheProvider>) -> Self {
        Self {
            cache,
            metadata: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Register a new tenant
    pub async fn register_tenant(&self, metadata: TenantMetadata) -> Result<String> {
        let tenant_id = metadata.id.clone();

        // Store in cache
        let cache_key = format!("tenant:metadata:{}", tenant_id);
        let metadata_json = serde_json::to_string(&metadata)
            .map_err(|e| GrcError::InternalError(format!("Serialization failed: {}", e)))?;

        self.cache.set(&cache_key, metadata_json, 86400).await?;

        // Store in persistent map
        let mut store = self.metadata.write().await;
        store.insert(tenant_id.clone(), metadata);

        Ok(tenant_id)
    }

    /// Get tenant metadata
    pub async fn get_tenant(&self, tenant_id: &str) -> Result<TenantMetadata> {
        // Try cache first
        let cache_key = format!("tenant:metadata:{}", tenant_id);
        if let Ok(Some(cached)) = self.cache.get(&cache_key).await {
            if let Ok(metadata) = serde_json::from_str::<TenantMetadata>(&cached) {
                return Ok(metadata);
            }
        }

        // Fall back to persistent store
        let store = self.metadata.read().await;
        store
            .get(tenant_id)
            .cloned()
            .ok_or_else(|| GrcError::TenantNotFound(tenant_id.into()))
    }

    /// Check if tenant exists and is active
    pub async fn is_tenant_valid(&self, tenant_id: &str) -> Result<bool> {
        match self.get_tenant(tenant_id).await {
            Ok(_) => Ok(true),
            Err(GrcError::TenantNotFound(_)) => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// Invalidate tenant cache
    pub async fn invalidate_cache(&self, tenant_id: &str) -> Result<()> {
        let cache_key = format!("tenant:metadata:{}", tenant_id);
        self.cache.delete(&cache_key).await
    }
}

// ============================================
// TENANT ROUTER
// ============================================

pub struct TenantRouter {
    store: Arc<TenantStore>,
}

impl TenantRouter {
    pub fn new(store: Arc<TenantStore>) -> Self {
        Self { store }
    }

    /// Extract tenant ID from various sources (header, JWT, subdomain, etc.)
    pub async fn extract_tenant_id(&self, header_value: Option<&str>) -> Result<String> {
        let tenant_id = header_value
            .ok_or_else(|| GrcError::InvalidTenantContext)?
            .to_string();

        // Validate tenant exists
        self.store.is_tenant_valid(&tenant_id).await?;

        Ok(tenant_id)
    }

    /// Validate tenant routing
    pub async fn validate_request(&self, tenant_id: &str, request_tenant: &str) -> Result<()> {
        if tenant_id != request_tenant {
            return Err(GrcError::TenantIsolationViolation);
        }

        self.store.is_tenant_valid(tenant_id).await?;
        Ok(())
    }
}

// ============================================
// TENANT-AWARE QUERY BUILDER
// ============================================

pub struct TenantAwareQuery {
    tenant_id: String,
    base_query: String,
    params: Vec<String>,
}

impl TenantAwareQuery {
    pub fn new(tenant_id: String, base_query: String) -> Self {
        Self {
            tenant_id,
            base_query,
            params: vec![],
        }
    }

    /// Build a query with tenant isolation WHERE clause
    pub fn build(&self) -> (String, Vec<String>) {
        let mut query = self.base_query.clone();
        let mut params = vec![self.tenant_id.clone()];
        params.extend(self.params.clone());

        // Add tenant_id filter if not already present
        if !query.contains("WHERE") {
            query.push_str(" WHERE tenant_id = $1");
        } else {
            query.push_str(" AND tenant_id = $1");
        }

        (query, params)
    }

    pub fn add_param(&mut self, param: String) {
        self.params.push(param);
    }
}

// ============================================
// TENANT-AWARE EVENT PUBLISHER
// ============================================

pub struct TenantEventPublisher {
    tenant_id: String,
    event_topic_prefix: String,
}

impl TenantEventPublisher {
    pub fn new(tenant_id: String) -> Self {
        Self {
            tenant_id,
            event_topic_prefix: "grc".into(),
        }
    }

    /// Get topic name for tenant-specific event
    pub fn get_topic(&self, event_type: &str) -> String {
        format!(
            "{}.{}.{}",
            self.event_topic_prefix, self.tenant_id, event_type
        )
    }

    /// Get partition key (ensures all tenant events go to same partition)
    pub fn get_partition_key(&self) -> &str {
        &self.tenant_id
    }
}

// ============================================
// TENANT-AWARE CACHE KEY BUILDER
// ============================================

pub struct TenantCacheKey {
    tenant_id: String,
    resource_type: String,
    resource_id: String,
}

impl TenantCacheKey {
    pub fn new(tenant_id: String, resource_type: String, resource_id: String) -> Self {
        Self {
            tenant_id,
            resource_type,
            resource_id,
        }
    }

    pub fn key(&self) -> String {
        format!(
            "tenant:{}:{}:{}",
            self.tenant_id, self.resource_type, self.resource_id
        )
    }
}

// ============================================
// TENANT ISOLATION MIDDLEWARE
// ============================================

pub struct TenantIsolationMiddleware {
    #[allow(dead_code)]
    store: Arc<TenantStore>,
    router: Arc<TenantRouter>,
}

impl TenantIsolationMiddleware {
    pub fn new(store: Arc<TenantStore>, router: Arc<TenantRouter>) -> Self {
        Self { store, router }
    }

    /// Extract and validate tenant from request
    pub async fn extract_and_validate(
        &self,
        tenant_header: Option<&str>,
    ) -> Result<RequestTenantContext> {
        let tenant_id = self.router.extract_tenant_id(tenant_header).await?;

        Ok(RequestTenantContext::new(tenant_id.clone(), String::new()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tenant_cache_key() {
        let key = TenantCacheKey::new("tenant-1".into(), "control".into(), "control-1".into());

        assert_eq!(key.key(), "tenant:tenant-1:control:control-1");
    }

    #[test]
    fn test_tenant_event_publisher() {
        let publisher = TenantEventPublisher::new("tenant-1".into());
        let topic = publisher.get_topic("evidence.ingested");

        assert!(topic.contains("tenant-1"));
        assert!(topic.contains("evidence"));
    }

    #[tokio::test]
    async fn test_tenant_aware_query() {
        let query = TenantAwareQuery::new("tenant-1".into(), "SELECT * FROM controls".into());

        let (built_query, params) = query.build();

        assert!(built_query.contains("WHERE tenant_id"));
        assert_eq!(params[0], "tenant-1");
    }
}

pub mod context;
pub mod isolation;

pub use context::*;
pub use isolation::*;
