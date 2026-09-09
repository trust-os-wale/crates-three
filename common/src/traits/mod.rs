use crate::errors::Result;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ============================================
// REPOSITORY TRAITS
// ============================================

/// Generic repository trait for CRUD operations
#[async_trait]
pub trait Repository<T: Send + Sync> {
    async fn create(&self, entity: T) -> Result<String>;
    async fn get(&self, id: &str) -> Result<Option<T>>;
    async fn update(&self, id: &str, entity: T) -> Result<()>;
    async fn delete(&self, id: &str) -> Result<()>;
    async fn list(&self, filter: &str, limit: i32, offset: i32) -> Result<Vec<T>>;
    async fn count(&self, filter: &str) -> Result<i64>;
}

// ============================================
// EVENT TRAITS
// ============================================

/// Trait for domain events
pub trait DomainEvent: Serialize + Send + Sync {
    fn event_type(&self) -> &'static str;
    fn event_version(&self) -> u32;
    fn aggregate_id(&self) -> String;
    fn tenant_id(&self) -> String;
    fn occurred_at(&self) -> DateTime<Utc>;
}

/// Event publisher for emitting domain events
#[async_trait]
pub trait EventPublisher: Send + Sync {
    async fn publish<T: DomainEvent>(&self, event: T) -> Result<String>;
    async fn publish_batch(&self, events: Vec<serde_json::Value>) -> Result<usize>;
}

/// Event consumer for processing events
#[async_trait]
pub trait EventConsumer: Send + Sync {
    async fn subscribe(&self, topic: &str) -> Result<()>;
    async fn unsubscribe(&self, topic: &str) -> Result<()>;
    async fn start_consuming(&self) -> Result<()>;
    async fn stop_consuming(&self) -> Result<()>;
}

// ============================================
// EVIDENCE TRAITS
// ============================================

/// Evidence validation strategy
#[async_trait]
pub trait EvidenceValidator: Send + Sync {
    async fn validate(&self, evidence: &[u8]) -> Result<EvidenceValidationResult>;
}

/// Evidence storage provider
#[async_trait]
pub trait EvidenceStorage: Send + Sync {
    async fn store(&self, tenant_id: &str, evidence: &[u8]) -> Result<String>;
    async fn retrieve(&self, tenant_id: &str, evidence_id: &str) -> Result<Vec<u8>>;
    async fn delete(&self, tenant_id: &str, evidence_id: &str) -> Result<()>;
    async fn exists(&self, tenant_id: &str, evidence_id: &str) -> Result<bool>;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceValidationResult {
    pub valid: bool,
    pub score: f32,
    pub issues: Vec<String>,
}

// ============================================
// COMPLIANCE TRAITS
// ============================================

/// Compliance rule evaluator
#[async_trait]
pub trait ComplianceEvaluator: Send + Sync {
    async fn evaluate_control(
        &self,
        tenant_id: &str,
        control_id: &str,
    ) -> Result<ComplianceEvaluationResult>;

    async fn evaluate_all_controls(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<ComplianceEvaluationResult>>;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceEvaluationResult {
    pub control_id: String,
    pub status: String,
    pub score: f32,
    pub evidence_count: i32,
    pub issues: Vec<String>,
}

// ============================================
// RISK TRAITS
// ============================================

/// Risk calculator and propagator
#[async_trait]
pub trait RiskCalculator: Send + Sync {
    async fn calculate_risk(
        &self,
        tenant_id: &str,
        source_type: &str,
        source_id: &str,
    ) -> Result<RiskCalculationResult>;

    async fn propagate_risk(
        &self,
        tenant_id: &str,
        risk_id: &str,
    ) -> Result<Vec<RiskCalculationResult>>;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskCalculationResult {
    pub risk_id: String,
    pub likelihood: f32,
    pub impact: f32,
    pub risk_score: f32,
    pub affected_resources: Vec<String>,
}

// ============================================
// TRUST SCORE TRAITS
// ============================================

/// Trust score computation engine
#[async_trait]
pub trait TrustScoreComputer: Send + Sync {
    async fn compute_trust_score(&self, tenant_id: &str) -> Result<TrustScoreResult>;
    async fn get_trust_history(&self, tenant_id: &str, days: i32) -> Result<Vec<TrustScoreResult>>;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustScoreResult {
    pub overall_score: f32,
    pub compliance_component: f32,
    pub risk_component: f32,
    pub evidence_quality_component: f32,
    pub governance_component: f32,
    pub computed_at: DateTime<Utc>,
}

// ============================================
// GRAPH TRAITS
// ============================================

/// Graph database operations
#[async_trait]
pub trait GraphOperations: Send + Sync {
    async fn create_node(
        &self,
        node_type: &str,
        properties: HashMap<String, String>,
    ) -> Result<String>;

    async fn create_relationship(
        &self,
        from_node_id: &str,
        relationship_type: &str,
        to_node_id: &str,
        properties: HashMap<String, String>,
    ) -> Result<()>;

    async fn query_relationships(&self, from_node_id: &str) -> Result<Vec<GraphRelationship>>;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphRelationship {
    pub from_id: String,
    pub to_id: String,
    pub relationship_type: String,
    pub properties: HashMap<String, String>,
}

// ============================================
// AUTHENTICATION TRAITS
// ============================================

/// Authentication provider
#[async_trait]
pub trait AuthenticationProvider: Send + Sync {
    async fn authenticate(&self, username: &str, password: &str) -> Result<AuthToken>;
    async fn verify_token(&self, token: &str) -> Result<TokenClaims>;
    async fn refresh_token(&self, refresh_token: &str) -> Result<AuthToken>;
    async fn revoke_token(&self, token: &str) -> Result<()>;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthToken {
    pub access_token: String,
    pub refresh_token: String,
    pub token_type: String,
    pub expires_in: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenClaims {
    pub user_id: String,
    pub tenant_id: String,
    pub roles: Vec<String>,
    pub permissions: Vec<String>,
    pub exp: i64,
}

// ============================================
// AUTHORIZATION TRAITS
// ============================================

/// Authorization provider
#[async_trait]
pub trait AuthorizationProvider: Send + Sync {
    async fn check_permission(
        &self,
        user_id: &str,
        action: &str,
        resource_type: &str,
    ) -> Result<bool>;

    async fn get_user_permissions(&self, user_id: &str) -> Result<Vec<String>>;
    async fn get_user_roles(&self, user_id: &str) -> Result<Vec<String>>;
}

// ============================================
// CACHE TRAITS
// ============================================

/// Cache provider
#[async_trait]
pub trait CacheProvider: Send + Sync {
    async fn get(&self, key: &str) -> Result<Option<String>>;
    async fn set(&self, key: &str, value: String, ttl_seconds: u64) -> Result<()>;
    async fn delete(&self, key: &str) -> Result<()>;
    async fn exists(&self, key: &str) -> Result<bool>;
    async fn increment(&self, key: &str) -> Result<i64>;
    async fn decrement(&self, key: &str) -> Result<i64>;
}

// ============================================
// NOTIFICATION TRAITS
// ============================================

/// Notification delivery provider
#[async_trait]
pub trait NotificationProvider: Send + Sync {
    async fn send_email(&self, to: &str, subject: &str, body: &str) -> Result<String>;
    async fn send_slack(&self, webhook_url: &str, message: &str) -> Result<String>;
    async fn send_sms(&self, phone: &str, message: &str) -> Result<String>;
    async fn send_webhook(&self, url: &str, payload: serde_json::Value) -> Result<String>;
}

// ============================================
// WORKFLOW TRAITS
// ============================================

/// Workflow orchestrator
#[async_trait]
pub trait WorkflowOrchestrator: Send + Sync {
    async fn create_workflow(
        &self,
        workflow_type: &str,
        trigger_event: &str,
        trigger_source_id: &str,
    ) -> Result<String>;

    async fn execute_workflow(&self, workflow_id: &str) -> Result<()>;
    async fn get_workflow_status(&self, workflow_id: &str) -> Result<String>;
    async fn cancel_workflow(&self, workflow_id: &str) -> Result<()>;
}

// ============================================
// OBSERVABILITY TRAITS
// ============================================

/// Observability provider
pub trait ObservabilityProvider: Send + Sync {
    fn create_span(&self, name: &str) -> Result<()>;
    fn record_metric(&self, name: &str, value: f64, tags: HashMap<String, String>) -> Result<()>;
    fn record_event(&self, event_type: &str, properties: HashMap<String, String>) -> Result<()>;
}

// ============================================
// HEALTH CHECK TRAITS
// ============================================

/// Health check provider
#[async_trait]
pub trait HealthCheckProvider: Send + Sync {
    async fn check_database(&self) -> Result<bool>;
    async fn check_cache(&self) -> Result<bool>;
    async fn check_event_bus(&self) -> Result<bool>;
    async fn check_graph_db(&self) -> Result<bool>;
    async fn get_overall_status(&self) -> Result<SystemHealth>;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemHealth {
    pub status: String,
    pub database: bool,
    pub cache: bool,
    pub event_bus: bool,
    pub graph_db: bool,
    pub timestamp: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token_claims_structure() {
        let claims = TokenClaims {
            user_id: "user-1".into(),
            tenant_id: "tenant-1".into(),
            roles: vec!["admin".into()],
            permissions: vec!["read".into(), "write".into()],
            exp: 1000000,
        };

        assert_eq!(claims.user_id, "user-1");
        assert_eq!(claims.roles.len(), 1);
    }
}
