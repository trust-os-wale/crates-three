use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Global error type for all Trust OS operations
#[derive(Error, Debug, Clone, Serialize, Deserialize)]
pub enum GrcError {
    // Authentication & Authorization errors
    #[error("Authentication failed: {0}")]
    AuthenticationFailed(String),

    #[error("Authorization failed: insufficient permissions")]
    AuthorizationFailed,

    #[error("Invalid token: {0}")]
    InvalidToken(String),

    #[error("Token expired")]
    TokenExpired,

    #[error("MFA challenge required")]
    MfaChallengeRequired,

    #[error("MFA verification failed")]
    MfaVerificationFailed,

    // Tenant errors
    #[error("Tenant not found: {0}")]
    TenantNotFound(String),

    #[error("Tenant isolation violation")]
    TenantIsolationViolation,

    #[error("Invalid tenant context")]
    InvalidTenantContext,

    // Evidence errors
    #[error("Evidence not found: {0}")]
    EvidenceNotFound(String),

    #[error("Evidence validation failed: {0}")]
    EvidenceValidationFailed(String),

    #[error("Evidence duplicate detected")]
    EvidenceDuplicate,

    #[error("Invalid evidence signature")]
    InvalidEvidenceSignature,

    // Compliance errors
    #[error("Control not found: {0}")]
    ControlNotFound(String),

    #[error("Compliance evaluation failed: {0}")]
    ComplianceEvaluationFailed(String),

    #[error("Invalid policy expression: {0}")]
    InvalidPolicyExpression(String),

    // Risk errors
    #[error("Risk calculation failed: {0}")]
    RiskCalculationFailed(String),

    #[error("Risk propagation failed")]
    RiskPropagationFailed,

    // Trust score errors
    #[error("Trust score computation failed: {0}")]
    TrustScoreComputationFailed(String),

    // Graph errors
    #[error("Graph operation failed: {0}")]
    GraphOperationFailed(String),

    #[error("Graph node not found: {0}")]
    GraphNodeNotFound(String),

    // Database errors
    #[error("Database error: {0}")]
    DatabaseError(String),

    #[error("Database query failed")]
    DatabaseQueryFailed,

    #[error("Transaction failed: {0}")]
    TransactionFailed(String),

    // Event errors
    #[error("Event publishing failed: {0}")]
    EventPublishingFailed(String),

    #[error("Event consumption failed: {0}")]
    EventConsumptionFailed(String),

    // Cache errors
    #[error("Cache operation failed: {0}")]
    CacheError(String),

    // Configuration errors
    #[error("Invalid configuration: {0}")]
    InvalidConfiguration(String),

    #[error("Missing configuration: {0}")]
    MissingConfiguration(String),

    // API errors
    #[error("Invalid request: {0}")]
    InvalidRequest(String),

    #[error("Request validation failed: {0}")]
    ValidationFailed(String),

    #[error("Rate limit exceeded")]
    RateLimitExceeded,

    // Generic errors
    #[error("Internal error: {0}")]
    InternalError(String),

    #[error("Unsupported operation: {0}")]
    UnsupportedOperation(String),

    #[error("Not implemented: {0}")]
    NotImplemented(String),

    // Crypto errors
    #[error("Cryptographic operation failed: {0}")]
    CryptoError(String),

    #[error("Key generation failed")]
    KeyGenerationFailed,

    #[error("Signature verification failed")]
    SignatureVerificationFailed,

    // Workflow errors
    #[error("Workflow not found: {0}")]
    WorkflowNotFound(String),

    #[error("Workflow execution failed: {0}")]
    WorkflowExecutionFailed(String),

    #[error("Invalid workflow state: {0}")]
    InvalidWorkflowState(String),

    // Integration errors
    #[error("Integration failed: {0}")]
    IntegrationFailed(String),

    #[error("External service error: {0}")]
    ExternalServiceError(String),

    // Timeout errors
    #[error("Operation timeout: {0}")]
    OperationTimeout(String),

    // Conflict errors
    #[error("Resource conflict: {0}")]
    ResourceConflict(String),
}

impl GrcError {
    /// Get HTTP status code for this error
    pub fn status_code(&self) -> u16 {
        match self {
            GrcError::AuthenticationFailed(_) => 401,
            GrcError::AuthorizationFailed => 403,
            GrcError::InvalidToken(_) => 401,
            GrcError::TokenExpired => 401,
            GrcError::MfaChallengeRequired => 403,
            GrcError::MfaVerificationFailed => 403,
            GrcError::TenantNotFound(_) => 404,
            GrcError::TenantIsolationViolation => 403,
            GrcError::InvalidTenantContext => 400,
            GrcError::EvidenceNotFound(_) => 404,
            GrcError::EvidenceValidationFailed(_) => 400,
            GrcError::EvidenceDuplicate => 409,
            GrcError::InvalidEvidenceSignature => 400,
            GrcError::ControlNotFound(_) => 404,
            GrcError::ComplianceEvaluationFailed(_) => 500,
            GrcError::InvalidPolicyExpression(_) => 400,
            GrcError::RiskCalculationFailed(_) => 500,
            GrcError::RiskPropagationFailed => 500,
            GrcError::TrustScoreComputationFailed(_) => 500,
            GrcError::GraphOperationFailed(_) => 500,
            GrcError::GraphNodeNotFound(_) => 404,
            GrcError::DatabaseError(_) => 500,
            GrcError::DatabaseQueryFailed => 500,
            GrcError::TransactionFailed(_) => 500,
            GrcError::EventPublishingFailed(_) => 500,
            GrcError::EventConsumptionFailed(_) => 500,
            GrcError::CacheError(_) => 500,
            GrcError::InvalidConfiguration(_) => 500,
            GrcError::MissingConfiguration(_) => 500,
            GrcError::InvalidRequest(_) => 400,
            GrcError::ValidationFailed(_) => 400,
            GrcError::RateLimitExceeded => 429,
            GrcError::InternalError(_) => 500,
            GrcError::UnsupportedOperation(_) => 400,
            GrcError::NotImplemented(_) => 501,
            GrcError::CryptoError(_) => 500,
            GrcError::KeyGenerationFailed => 500,
            GrcError::SignatureVerificationFailed => 400,
            GrcError::WorkflowNotFound(_) => 404,
            GrcError::WorkflowExecutionFailed(_) => 500,
            GrcError::InvalidWorkflowState(_) => 400,
            GrcError::IntegrationFailed(_) => 500,
            GrcError::ExternalServiceError(_) => 502,
            GrcError::OperationTimeout(_) => 504,
            GrcError::ResourceConflict(_) => 409,
        }
    }

    /// Check if this is a retryable error
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            GrcError::OperationTimeout(_)
                | GrcError::ExternalServiceError(_)
                | GrcError::DatabaseError(_)
                | GrcError::EventPublishingFailed(_)
                | GrcError::CacheError(_)
        )
    }

    /// Check if this is a security-related error
    pub fn is_security_error(&self) -> bool {
        matches!(
            self,
            GrcError::AuthenticationFailed(_)
                | GrcError::AuthorizationFailed
                | GrcError::InvalidToken(_)
                | GrcError::TokenExpired
                | GrcError::MfaChallengeRequired
                | GrcError::MfaVerificationFailed
                | GrcError::TenantIsolationViolation
                | GrcError::InvalidEvidenceSignature
                | GrcError::SignatureVerificationFailed
                | GrcError::CryptoError(_)
        )
    }
}

/// Result type alias for GRC operations
pub type Result<T> = std::result::Result<T, GrcError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_status_codes() {
        assert_eq!(
            GrcError::AuthenticationFailed("test".into()).status_code(),
            401
        );
        assert_eq!(GrcError::AuthorizationFailed.status_code(), 403);
        assert_eq!(GrcError::TenantNotFound("test".into()).status_code(), 404);
        assert_eq!(GrcError::RateLimitExceeded.status_code(), 429);
        assert_eq!(GrcError::NotImplemented("test".into()).status_code(), 501);
    }

    #[test]
    fn test_retryable_errors() {
        assert!(GrcError::OperationTimeout("test".into()).is_retryable());
        assert!(GrcError::ExternalServiceError("test".into()).is_retryable());
        assert!(!GrcError::AuthenticationFailed("test".into()).is_retryable());
    }

    #[test]
    fn test_security_errors() {
        assert!(GrcError::AuthenticationFailed("test".into()).is_security_error());
        assert!(GrcError::InvalidToken("test".into()).is_security_error());
        assert!(!GrcError::TenantNotFound("test".into()).is_security_error());
    }
}
